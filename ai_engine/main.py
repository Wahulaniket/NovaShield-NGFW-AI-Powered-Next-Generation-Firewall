"""
NovaShield AI Engine — FastAPI service for real-time threat classification.

Accepts HTTP request metadata from the Rust gateway and returns allow/block
decisions using a Random Forest model trained on CICIDS2017 network traffic data.
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from model import predict, predict_batch, warmup

logger = logging.getLogger("ai_engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load model artifacts at startup to avoid cold-start latency."""
    logger.info("Loading ML model artifacts...")
    warmup()
    logger.info("Model loaded and ready for predictions")
    yield


app = FastAPI(
    title="NovaShield AI Engine",
    description=(
        "Machine learning threat classification service for the NovaShield "
        "Next-Generation Firewall. Analyses HTTP request metadata and network "
        "flow features to classify traffic as benign or malicious."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response schemas ────────────────────────────────────────────────


class RequestData(BaseModel):
    """Input schema for single prediction.

    Supports three input modes:
    1. ``feature_vector``: pre-ordered list of floats matching model features.
    2. ``features``: dict mapping feature names to values.
    3. Gateway metadata fields (``ip``, ``path``, ``method``, ``user_agent``).
    """

    features: Optional[Dict[str, float]] = None
    feature_vector: Optional[List[float]] = None

    # Gateway-injected metadata
    ip: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    user_agent: Optional[str] = None


class BatchRequestData(BaseModel):
    """Input schema for batch prediction."""

    items: List[RequestData]


class PredictionResponse(BaseModel):
    """Standardised prediction output consumed by the Rust gateway."""

    decision: str  # "allow" or "block"
    label: str
    confidence: Optional[float] = None
    latency_ms: Optional[float] = None


class BatchPredictionResponse(BaseModel):
    results: List[PredictionResponse]


class HealthResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    service: str = "ai_engine"
    status: str = "ok"
    model_loaded: bool = True


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/", tags=["status"])
async def home():
    """Root endpoint — confirms the service is running."""
    return {"message": "NovaShield AI Engine Running", "version": "1.0.0"}


@app.get("/health", response_model=HealthResponse, tags=["status"])
async def health():
    """Health check endpoint used by Docker and orchestrators."""
    return HealthResponse()


@app.post("/predict", response_model=PredictionResponse, tags=["inference"])
async def predict_route(data: RequestData):
    """Classify a single HTTP request as benign or malicious.

    The gateway sends request metadata (IP, path, method, user-agent). The
    engine extracts features, runs them through the trained model, and returns
    an allow/block decision.
    """
    start = time.monotonic()
    result = predict(data.model_dump())
    elapsed_ms = (time.monotonic() - start) * 1000

    label = str(result.get("label", "UNKNOWN")).strip().upper()
    decision = "allow" if label == "BENIGN" else "block"

    return PredictionResponse(
        decision=decision,
        label=label,
        confidence=result.get("confidence"),
        latency_ms=round(elapsed_ms, 2),
    )


@app.post(
    "/predict/batch",
    response_model=BatchPredictionResponse,
    tags=["inference"],
)
async def predict_batch_route(data: BatchRequestData):
    """Classify multiple requests in a single call for higher throughput."""
    start = time.monotonic()
    items = [item.model_dump() for item in data.items]
    results = predict_batch(items)
    elapsed_ms = (time.monotonic() - start) * 1000

    responses = []
    for result in results:
        label = str(result.get("label", "UNKNOWN")).strip().upper()
        decision = "allow" if label == "BENIGN" else "block"
        responses.append(
            PredictionResponse(
                decision=decision,
                label=label,
                confidence=result.get("confidence"),
                latency_ms=round(elapsed_ms / len(items), 2),
            )
        )

    return BatchPredictionResponse(results=responses)
