from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
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
from app.demo.service import DemoSampleService
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.service import LabService
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.config import PcapConfig
from app.pcap.executor import PcapBatchExecutor
from app.superagent.pcap_coordinator import PcapMissionCoordinator
from app.superagent.service import SuperAgentService


PRODUCT_NAME = "面向AI安全的Token流量异常检测智能体平台"
logger = logging.getLogger(__name__)
_LIFESPAN_STATE_NAMES = (
    "active_calibration_version",
    "analysis_workflow",
    "demo_service",
    "evaluation_service",
    "event_store",
    "lab_enabled",
    "lab_service",
    "pcap_authorization_store",
    "pcap_coordinator",
    "pcap_executor",
    "service_health",
    "superagent_service",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    _clear_lifespan_state(application)
    event_store = None
    lab_execution_store = None
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
    try:
        pcap_config = PcapConfig.from_environ(os.environ)
        if pcap_config is not None:
            authorization_store = PcapAuthorizationStore()
            executor = PcapBatchExecutor(config=pcap_config)
            pcap_coordinator = PcapMissionCoordinator(
                authorization_store=authorization_store,
                executor=executor,
            )
            application.state.pcap_authorization_store = authorization_store
            application.state.pcap_executor = executor
            application.state.pcap_coordinator = pcap_coordinator
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
