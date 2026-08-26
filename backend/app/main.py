from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from app.api.analyze import router as analyze_router
from app.api.events import router as events_router
from app.api.evaluation import router as evaluation_router
from app.api.demo import router as demo_router
from app.audit.store import SQLiteEventStore
from app.bootstrap import (
    ServiceConfig,
    agent_ablation_paths_from_environ,
    benchmark_report_path_from_environ,
    demo_source_paths_from_environ,
    event_db_path_from_environ,
    knowledge_evaluation_report_path_from_environ,
    load_service_bundle,
)
from app.evaluation.service import EvaluationReportService
from app.demo.service import DemoSampleService


PRODUCT_NAME = "面向AI安全的Token流量异常检测智能体平台"
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI):
    event_store = None
    audit_health: dict[str, Any] = {"ready": False, "storage": None}
    try:
        event_store = SQLiteEventStore(event_db_path_from_environ(os.environ))
        application.state.event_store = event_store
        audit_health = {"ready": True, "storage": "sqlite"}
    except Exception as exc:
        logger.error("event audit initialization failed error_type=%s", type(exc).__name__)

    config = ServiceConfig.from_environ(os.environ)
    active_calibration_version = None
    if config is not None:
        bundle = load_service_bundle(config)
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
    application.state.service_health = {
        **base_health,
        "evaluation": evaluation_health,
        "demo": demo_health,
    }
    try:
        yield
    finally:
        if event_store is not None:
            event_store.close()


app = FastAPI(title=PRODUCT_NAME, version="0.1.0", lifespan=lifespan)
app.include_router(analyze_router)
app.include_router(events_router)
app.include_router(evaluation_router)
app.include_router(demo_router)


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
    }
