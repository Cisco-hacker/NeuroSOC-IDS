#!/usr/bin/env python3

"""
SOCortex-IDS Model Server

FastAPI-based machine learning inference service for
network intrusion detection.

The service receives CICIDS2017-compatible network flow
features through a REST API and returns Attack/Benign
predictions with confidence scores.

Model:
    XGBoost Classifier

Dataset:
    CICIDS2017
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from xgboost import XGBClassifier
import joblib
import numpy as np
import pandas as pd
import os
import logging

# ── Logging Setup ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ── FastAPI App ─────────────────────────────────────────────────
app = FastAPI(
    title="IDS Model Server",
    description="Intrusion Detection System API — CICIDS2017 XGBoost",
    version="1.0.0"
)


# ── Load Model Artifacts at Startup ────────────────────────────
# These are loaded ONCE when the server starts, then kept in
# memory for fast predictions. Loading on every request would
# be extremely slow.
MODEL_DIR = "ids_model"

try:
    # Load the trained XGBoost model
    model = XGBClassifier()
    model.load_model(os.path.join(MODEL_DIR, "xgb_model.json"))

    # Load the ordered list of model feature names
    # CRITICAL: features must be in this exact order for predictions
    feature_cols = joblib.load(os.path.join(MODEL_DIR, "feature_cols.pkl"))

    logger.info(f"✅ Model loaded successfully")
    logger.info(f"✅ Features expected: {len(feature_cols)}")
    logger.info(f"✅ Feature list: {feature_cols}")

except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")
    raise


# ── Request & Response Schemas ──────────────────────────────────
# These define exactly what data the API accepts and returns.
# Pydantic validates incoming data automatically.

class FlowFeatures(BaseModel):
    """
    Input: a dictionary of feature names and their values.
    Example:
    {
        "features": {
            "Protocol": 6,
            "Flow Duration": 75271,
            "Total Fwd Packets": 28,
            ...
        }
    }
    """
    features: dict


class PredictionResponse(BaseModel):
    """
    Output: prediction label, confidence score, and alert flag.
    Example:
    {
        "prediction": "Attack",
        "confidence": 0.8823,
        "alert": true
    }
    """
    prediction: str    # "Benign" or "Attack"
    confidence: float  # probability 0.0 to 1.0
    alert: bool        # True if attack detected


# ── Endpoints ───────────────────────────────────────────────────

@app.get("/")
def root():
    """
    Root endpoint — quick sanity check that the server is running.
    Visit http://localhost:8000/ in a browser to confirm.
    """
    return {
        "status":            "running",
        "model":             "XGBoost CICIDS2017",
        "features_expected": len(feature_cols)
    }


@app.get("/health")
def health():

    """
    Health check endpoint.

    Allows external clients, replay tools, and monitoring
    systems to verify that the model server is operational.
    """
    
    return {"status": "healthy"}


@app.get("/features")
def get_features():
    """
    Returns the exact list of model features.

    Useful for validation, debugging, and external clients
    that need to dynamically build compatible requests.
    """
    return {
        "count":    len(feature_cols),
        "features": feature_cols
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(flow: FlowFeatures):
    """

    Main prediction endpoint.

    Accepts a CICIDS2017-compatible network flow feature
    dictionary and returns an intrusion detection prediction.

    Returns:
        - prediction (Attack / Benign)
        - confidence score
        - alert flag

    Features are automatically aligned to the model's
    expected feature order before inference.

    Process:
    1. Build DataFrame from incoming features
    2. Add any missing features as 0 (safe default)
    3. Reorder columns to match training order exactly
    4. Run through XGBoost model
    5. Return prediction + confidence
    """
    try:
        # Step 1: Convert incoming feature dict to a DataFrame
        # (a table with one row — one network flow)
        input_df = pd.DataFrame([flow.features])

        # Step 2: Add any missing features as 0
        # This allows partial feature submissions while
        # preserving compatibility with the trained model.
        missing_features = []
        for col in feature_cols:
            if col not in input_df.columns:
                input_df[col] = 0
                missing_features.append(col)

        if missing_features:
            logger.debug(f"Missing features set to 0: {missing_features}")

        # Step 3: Reorder columns to EXACTLY match training order
        # The model internally refers to features by position
        # (column 0, column 1, etc.) not by name.
        # Wrong order = completely wrong predictions.
        input_df = input_df[feature_cols]

        # Step 4: Run through the XGBoost model
        # predict()       → hard label: 0 (Benign) or 1 (Attack)
        # predict_proba() → soft probabilities: [P(Benign), P(Attack)]
        proba = model.predict_proba(input_df)[0]
        pred  = int(model.predict(input_df)[0])

        # Step 5: Format the results
        confidence = float(proba[pred])        # confidence in the predicted class
        prediction = "Attack" if pred == 1 else "Benign"
        alert      = (pred == 1)

        # Step 6: Log the result
        if alert:
            logger.warning(
                f"🚨 ATTACK DETECTED | "
                f"confidence: {confidence:.4f} ({confidence:.2%})"
            )
        else:
            logger.info(
                f"✅ Benign traffic | "
                f"confidence: {confidence:.4f} ({confidence:.2%})"
            )

        # Step 7: Return the response
        return PredictionResponse(
            prediction=prediction,
            confidence=confidence,
            alert=alert
        )

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
def predict_batch(flows: list[FlowFeatures]):
    """
    Batch prediction endpoint.
    Accepts multiple flows at once and returns predictions for all.
    More efficient than calling /predict repeatedly.

    Returns:
    {
        "results": [...list of PredictionResponse...],
        "total": 10,
        "attacks": 3,
        "benign": 7
    }
    """
    results  = []
    attacks  = 0
    benign   = 0

    for flow in flows:
        result = predict(flow)
        results.append(result)
        if result.alert:
            attacks += 1
        else:
            benign += 1

    return {
        "results": results,
        "total":   len(results),
        "attacks": attacks,
        "benign":  benign
    }


@app.get("/stats")
def stats():
    """
    Returns model information and feature details.
    Useful for verifying the correct model is loaded.
    """
    return {
        "model_type":      "XGBoost Classifier",
        "dataset":         "CICIDS2017",
        "n_features":      len(feature_cols),
        "feature_names":   feature_cols,
        "classes":         ["Benign", "Attack"],
        "model_file":      "ids_model/xgb_model.json",
        "features_file":   "ids_model/feature_cols.pkl"
    }