from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.analyze import router as analyze_router
from app.api.events import router as events_router
from app.api.evaluation import router as evaluation_router
from app.api.demo import router as demo_router
from app.api.lab import router as lab_router
from app.api.superagent import router as superagent_router
from app.api.agent import router as agent_router
from app.audit.store import SQLiteEventStore
from app.bootstrap import (
    ServiceConfig,
    agent_ablation_paths_from_environ,
    benchmark_report_path_from_environ,
    demo_source_paths_from_environ,
    event_db_path_from_environ,
    knowledge_evaluation_report_path_from_environ,
    lab_enabled_from_environ,
    load_service_bundle,
)
from app.evaluation.service import EvaluationReportService
from app.evaluation.pcap_detection import load_pcap_evaluation
from app.demo.service import DemoSampleService
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.service import LabService
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.config import PcapConfig
from app.pcap.executor import PcapBatchExecutor
from app.pcap.detection_executor import PcapDetectionExecutor
from app.pcap.recon_executor import PcapReconExecutor
from app.pcap.upload import PcapUploadService
from app.superagent.pcap_coordinator import PcapMissionCoordinator
from app.superagent.pcap_recon_coordinator import PcapReconMissionCoordinator
from app.superagent.pcap_detection_coordinator import PcapDetectionMissionCoordinator
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore
from app.security_agent.coordinator import SecurityAgentCoordinator
from app.security_agent.dialogue import GroundedDialogueService
from app.security_agent.feedback import AnalystFeedbackService
from app.security_agent.models import AgentCapabilities
from app.security_agent.prompt_runtime import PromptAgentRuntime
from app.security_agent.simulated import SimulatedTelemetryConnector
from app.security_agent.store import SecurityAgentStore
from app.security_agent.tools import build_registry


PRODUCT_NAME = "面向AI安全的Token流量异常检测智能体平台"
logger = logging.getLogger(__name__)
_LIFESPAN_STATE_NAMES = (
    "active_calibration_version",
    "analysis_workflow",
    "demo_service",
    "evaluation_service",
    "pcap_evaluation_summary",
    "event_store",
    "lab_enabled",
    "lab_service",
    "pcap_authorization_store",
    "pcap_coordinator",
    "pcap_executor",
    "pcap_recon_coordinator",
    "pcap_recon_executor",
    "pcap_detection_coordinator",
    "pcap_detection_executor",
    "pcap_upload_service",
    "pcap_upload_max_bytes",
    "service_health",
    "superagent_service",
    "security_agent_coordinator",
    "security_agent_feedback",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    _clear_lifespan_state(application)
    event_store = None
    lab_execution_store = None
    security_agent_coordinator = None
    security_agent_feedback = None
    try:
        lab_enabled = lab_enabled_from_environ(os.environ)
        application.state.lab_enabled = lab_enabled
        audit_health: dict[str, Any] = {"ready": False, "storage": None}
        try:
            event_store = SQLiteEventStore(event_db_path_from_environ(os.environ))
            application.state.event_store = event_store
            audit_health = {"ready": True, "storage": "sqlite"}
        except Exception as exc:
            logger.error(
                "event audit initialization failed error_type=%s", type(exc).__name__
            )

        if lab_enabled:
            try:
                lab_execution_store = SQLiteLabExecutionStore(
                    event_db_path_from_environ(os.environ)
                )
            except Exception as exc:
                logger.error(
                    "lab tool storage initialization failed error_type=%s",
                    type(exc).__name__,
                )

        _initialize_lifespan_services(
            application,
            lab_enabled=lab_enabled,
            lab_execution_store=lab_execution_store,
            audit_health=audit_health,
        )
        try:
            security_agent_coordinator = _initialize_security_agent(application)
            database_value = os.environ.get(
                "TOKEN_SECURITY_AGENT_DATABASE_PATH", "tmp/security-agent.sqlite3"
            ).strip()
            security_agent_feedback = AnalystFeedbackService(
                Path(database_value),
                detector_identity=lambda: str(
                    getattr(application.state, "active_calibration_version", "unavailable")
                ),
            )
            application.state.security_agent_feedback = security_agent_feedback
        except Exception as exc:
            logger.error(
                "security agent initialization failed error_type=%s", type(exc).__name__
            )
        yield
    finally:
        try:
            pcap_coordinator = getattr(
                application.state, "pcap_coordinator", None
            )
            if pcap_coordinator is not None:
                try:
                    pcap_coordinator.close()
                except Exception as exc:
                    logger.error(
                        "pcap coordinator cleanup failed error_type=%s",
                        type(exc).__name__,
                    )
            pcap_recon_coordinator = getattr(application.state, "pcap_recon_coordinator", None)
            if pcap_recon_coordinator is not None:
                try:
                    pcap_recon_coordinator.close()
                except Exception as exc:
                    logger.error("pcap reconnaissance coordinator cleanup failed error_type=%s", type(exc).__name__)
            pcap_detection_coordinator = getattr(application.state, "pcap_detection_coordinator", None)
            if pcap_detection_coordinator is not None:
                try:
                    pcap_detection_coordinator.close()
                except Exception as exc:
                    logger.error("pcap detection coordinator cleanup failed error_type=%s", type(exc).__name__)
            pcap_upload_service = getattr(application.state, "pcap_upload_service", None)
            if pcap_upload_service is not None:
                try:
                    pcap_upload_service.close()
                except Exception as exc:
                    logger.error("pcap upload cleanup failed error_type=%s", type(exc).__name__)
        finally:
            try:
                if security_agent_feedback is not None:
                    security_agent_feedback.close()
            finally:
                try:
                    if security_agent_coordinator is not None:
                        security_agent_coordinator.close()
                finally:
                    try:
                        if lab_execution_store is not None:
                            lab_execution_store.close()
                    finally:
                        try:
                            if event_store is not None:
                                event_store.close()
                        finally:
                            _clear_lifespan_state(application)


def _initialize_lifespan_services(
    application: FastAPI,
    *,
    lab_enabled: bool,
    lab_execution_store: SQLiteLabExecutionStore | None,
    audit_health: dict[str, Any],
) -> None:
    config = ServiceConfig.from_environ(os.environ)
    active_calibration_version = None
    workflow = None
    if config is not None:
        bundle = load_service_bundle(config)
        workflow = bundle.workflow
        application.state.analysis_workflow = bundle.workflow
        active_calibration_version = bundle.health["detector"]["calibration_version"]
        application.state.active_calibration_version = active_calibration_version
        base_health = {**bundle.health, "audit": audit_health}
    else:
        base_health = {
            "status": "degraded",
            "api": {"ready": True},
            "model": {"ready": False, "model_id": None},
            "detector": {"ready": False, "calibration_version": None},
            "semantic_guard": {
                "ready": False,
                "model_id": "unconfigured",
                "model_version": "unconfigured",
            },
            "knowledge": {
                "ready": False,
                "snapshot_version": None,
                "card_count": 0,
                "generator_ready": False,
            },
            "audit": audit_health,
        }

    evaluation_health = {
        "ready": False,
        "schema_version": None,
        "deployment_match": False,
    }
    report_path = benchmark_report_path_from_environ(os.environ)
    evaluation_summary = None
    if report_path is not None:
        try:
            ablation_paths = agent_ablation_paths_from_environ(os.environ)
            evaluation_service = EvaluationReportService(
                report_path,
                knowledge_path=knowledge_evaluation_report_path_from_environ(
                    os.environ
                ),
                ablation_manifest_path=(
                    ablation_paths.manifest_path if ablation_paths is not None else None
                ),
                ablation_path=(
                    ablation_paths.report_path if ablation_paths is not None else None
                ),
            )
            summary = evaluation_service.load(
                active_calibration_version=active_calibration_version
            )
            application.state.evaluation_service = evaluation_service
            evaluation_summary = summary
            evaluation_health = {
                "ready": True,
                "schema_version": summary.schema_version,
                "deployment_match": summary.deployment_match,
                "knowledge_ready": summary.knowledge is not None,
                "agent_ablation_ready": summary.agent_ablation is not None,
                "agent_ablation_error_type": evaluation_service.ablation_error_type,
            }
        except Exception as exc:
            logger.error(
                "evaluation initialization failed error_type=%s", type(exc).__name__
            )
    try:
        pcap_evaluation_path = (
            Path(__file__).resolve().parents[2]
            / "data"
            / "pcap-detection-regression-v1.json"
        )
        application.state.pcap_evaluation_summary = load_pcap_evaluation(
            pcap_evaluation_path
        )
    except Exception as exc:
        logger.error(
            "pcap evaluation initialization failed error_type=%s", type(exc).__name__
        )
    demo_health = {"ready": False, "sample_count": 0}
    demo_service = None
    try:
        demo_paths = demo_source_paths_from_environ(os.environ)
        if (
            demo_paths is not None
            and evaluation_summary is not None
            and config is not None
        ):
            provenance = evaluation_summary.provenance.model_dump(mode="json")
            demo_service = DemoSampleService.from_paths(
                autodan_csv=demo_paths.autodan_csv,
                advprompter_csv=demo_paths.advprompter_csv,
                gcg_csv=demo_paths.gcg_csv,
                expected_hashes=provenance["source_files"],
                source_commit=provenance["cpdonline_commit"],
            )
            application.state.demo_service = demo_service
            demo_health = {
                "ready": True,
                "sample_count": demo_service.sample_count,
            }
    except Exception as exc:
        logger.error("demo initialization failed error_type=%s", type(exc).__name__)
    lab_health = {
        "enabled": lab_enabled,
        "ready": False,
        "reason": "disabled" if not lab_enabled else "unavailable",
    }
    if lab_enabled and lab_execution_store is None:
        lab_health = {
            "enabled": True,
            "ready": False,
            "reason": "tool_storage_unavailable",
            "tool_storage": None,
        }
    elif lab_enabled and workflow is None:
        lab_health = {
            "enabled": True,
            "ready": False,
            "reason": "unavailable",
            "tool_storage": "sqlite",
        }
    elif lab_enabled and workflow is not None:
        try:
            application.state.lab_service = LabService(
                workflow=workflow,
                demo_service=demo_service,
                execution_store=lab_execution_store,
            )
            lab_health = {
                "enabled": True,
                "ready": True,
                "reason": "ready",
                "tool_storage": "sqlite",
            }
        except Exception as exc:
            logger.error(
                "lab initialization failed error_type=%s", type(exc).__name__
            )
            lab_health = {
                "enabled": True,
                "ready": False,
                "reason": "unavailable",
                "tool_storage": "sqlite",
            }
    pcap_health = {"enabled": False, "ready": False, "reason": "disabled"}
    pcap_coordinator = None
    pcap_recon_coordinator = None
    pcap_detection_coordinator = None
    try:
        pcap_config = PcapConfig.from_environ(os.environ)
        if pcap_config is not None:
            authorization_store = PcapAuthorizationStore(
                upload_max_bytes=pcap_config.upload_max_bytes
            )
            executor = PcapBatchExecutor(config=pcap_config)
            mission_store = SuperAgentMissionStore()
            pcap_coordinator = PcapMissionCoordinator(
                authorization_store=authorization_store,
                executor=executor,
                mission_store=mission_store,
            )
            application.state.pcap_authorization_store = authorization_store
            application.state.pcap_executor = executor
            application.state.pcap_coordinator = pcap_coordinator
            try:
                recon_executor = PcapReconExecutor(config=pcap_config)
                pcap_recon_coordinator = PcapReconMissionCoordinator(
                    authorization_store=authorization_store,
                    executor=recon_executor,
                    mission_store=mission_store,
                )
                application.state.pcap_recon_executor = recon_executor
                application.state.pcap_recon_coordinator = pcap_recon_coordinator
            except Exception as exc:
                logger.error("pcap reconnaissance initialization failed error_type=%s", type(exc).__name__)
            try:
                detection_executor = PcapDetectionExecutor(config=pcap_config)
                upload_service = PcapUploadService(
                    pcap_config.quarantine_root,
                    max_bytes=pcap_config.upload_max_bytes,
                )
                pcap_detection_coordinator = PcapDetectionMissionCoordinator(
                    authorization_store=authorization_store,
                    executor=detection_executor,
                    mission_store=mission_store,
                    upload_service=upload_service,
                )
                application.state.pcap_detection_executor = detection_executor
                application.state.pcap_detection_coordinator = pcap_detection_coordinator
                application.state.pcap_upload_service = upload_service
                application.state.pcap_upload_max_bytes = pcap_config.upload_max_bytes
            except Exception as exc:
                logger.error("pcap detection initialization failed error_type=%s", type(exc).__name__)
            pcap_health = {
                "enabled": True,
                "ready": True,
                "reason": "ready",
            }
    except Exception as exc:
        logger.error(
            "pcap initialization failed error_type=%s", type(exc).__name__
        )
        pcap_health = {
            "enabled": True,
            "ready": False,
            "reason": "unavailable",
        }
    superagent_health = {
        "ready": False,
        "internal_only": True,
        "reason": "lab_unavailable",
    }
    lab_service = getattr(application.state, "lab_service", None)
    if lab_health.get("ready") is True and lab_service is not None:
        try:
            application.state.superagent_service = SuperAgentService(
                lab_service=lab_service,
                pcap_coordinator=pcap_coordinator,
                pcap_recon_coordinator=pcap_recon_coordinator,
                pcap_detection_coordinator=pcap_detection_coordinator,
            )
            superagent_health = {
                "ready": True,
                "internal_only": True,
                "max_tool_calls": 3,
                "max_trace_events": 12,
                "replanning_limit": 1,
            }
        except Exception as exc:
            logger.error(
                "superagent initialization failed error_type=%s",
                type(exc).__name__,
            )
    application.state.service_health = {
        **base_health,
        "evaluation": evaluation_health,
        "demo": demo_health,
        "lab": lab_health,
        "superagent": superagent_health,
        "pcap": pcap_health,
    }


def _clear_lifespan_state(application: FastAPI) -> None:
    for name in _LIFESPAN_STATE_NAMES:
        if hasattr(application.state, name):
            delattr(application.state, name)


def _initialize_security_agent(application: FastAPI) -> SecurityAgentCoordinator:
    database_value = os.environ.get(
        "TOKEN_SECURITY_AGENT_DATABASE_PATH", "tmp/security-agent.sqlite3"
    ).strip()
    if not database_value:
        raise ValueError("TOKEN_SECURITY_AGENT_DATABASE_PATH must not be blank")
    connector = SimulatedTelemetryConnector()
    workflow = getattr(application.state, "analysis_workflow", None)
    prompt_runtime = PromptAgentRuntime(workflow) if workflow is not None else None

    def simulated(arguments: dict[str, object]) -> dict[str, object]:
        case_id = str(arguments["case_id"])
        evidence = connector.query(case_id)
        return {
            "objective": "cross_domain_case",
            "status": "completed",
            "observation_kind": "direct_attack_signal",
            "summary": {
                "analyzed_count": len(evidence),
                "failed_count": 0,
                "evidence": [item.model_dump(mode="json") for item in evidence],
            },
        }

    def completed(tool_id: str, *, observation_kind: str | None = None):
        return lambda _arguments: {
            "objective": tool_id,
            "status": "completed",
            "observation_kind": observation_kind or f"{tool_id}_completed",
            "summary": f"{tool_id} 已完成平台内部结构化处理。",
        }

    handlers = {
        "query_simulated_telemetry": simulated,
        "retrieve_security_knowledge": completed("retrieve_security_knowledge"),
        "explain_attack": completed("explain_attack"),
        "explain_protocol": completed("explain_protocol"),
        "generate_case_report": completed("generate_case_report"),
        "preview_response_action": completed("preview_response_action"),
        "execute_internal_action": completed("execute_internal_action"),
        "map_attack_framework": completed("map_attack_framework"),
        "search_similar_cases": completed("search_similar_cases"),
        "simulate_response_options": completed("simulate_response_options"),
        "verify_response_effect": completed(
            "verify_response_effect", observation_kind="response_verified"
        ),
    }
    if prompt_runtime is not None:
        handlers.update(
            {
                "analyze_prompt": prompt_runtime.analyze_prompt,
                "counterfactual_recheck": prompt_runtime.counterfactual_recheck,
            }
        )
    registry = build_registry(handlers)
    capabilities = AgentCapabilities(
        planner_mode="deterministic_fallback",
        tool_ids=registry.ids(),
        connector_states={
            "prompt_runtime": (
                "available"
                if workflow is not None
                else "unavailable"
            ),
            "grounded_dialogue": (
                "available"
                if workflow is not None
                else "unavailable"
            ),
            "pcap_docker": (
                "available"
                if getattr(application.state, "pcap_detection_coordinator", None)
                is not None
                else "unavailable"
            ),
            "endpoint_demo": "simulated",
            "identity_demo": "simulated",
            "gateway_log_demo": "simulated",
        },
    )
    coordinator = SecurityAgentCoordinator(
        store=SecurityAgentStore(Path(database_value)),
        registry=registry,
        capabilities=capabilities,
        prompt_runtime=prompt_runtime,
        dialogue=GroundedDialogueService(
            workflow.runtime if workflow is not None else None
        ),
    )
    application.state.security_agent_coordinator = coordinator
    return coordinator


app = FastAPI(title=PRODUCT_NAME, version="0.1.0", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def request_validation_error(
    _request: Request, _error: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "request_validation_failed",
                "message": "request validation failed",
            }
        },
    )


app.include_router(analyze_router)
app.include_router(events_router)
app.include_router(evaluation_router)
app.include_router(demo_router)
app.include_router(lab_router)
app.include_router(superagent_router)
app.include_router(agent_router)


@app.get("/health")
def health() -> dict[str, Any]:
    return getattr(app.state, "service_health", None) or {
        "status": "degraded",
        "api": {"ready": True},
        "model": {"ready": False, "model_id": None},
        "detector": {"ready": False, "calibration_version": None},
        "semantic_guard": {
            "ready": False,
            "model_id": "unconfigured",
            "model_version": "unconfigured",
        },
        "knowledge": {
            "ready": False,
            "snapshot_version": None,
            "card_count": 0,
            "generator_ready": False,
        },
        "audit": {"ready": False, "storage": None},
        "evaluation": {
            "ready": False,
            "schema_version": None,
            "deployment_match": False,
        },
        "demo": {"ready": False, "sample_count": 0},
        "lab": {"enabled": False, "ready": False, "reason": "disabled"},
        "superagent": {
            "ready": False,
            "internal_only": True,
            "reason": "lab_unavailable",
        },
        "pcap": {"enabled": False, "ready": False, "reason": "disabled"},
    }
