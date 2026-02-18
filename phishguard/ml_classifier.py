"""Machine-learning phishing classifier loader and predictor."""

from __future__ import annotations

import pickle
import re
from pathlib import Path
from typing import Any, Dict

try:
    import joblib  # type: ignore
except Exception:  # pragma: no cover - fallback path when dependency is absent
    joblib = None


class PhishingClassifier:
    """Load pre-trained model artifacts and run phishing predictions."""

    def __init__(self, model_path: Path | None = None, vectorizer_path: Path | None = None) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.model_path = model_path or (project_root / "models" / "phishing_model.pkl")
        self.vectorizer_path = vectorizer_path or (project_root / "models" / "tfidf_vectorizer.pkl")

        if not self.model_path.exists() or not self.vectorizer_path.exists():
            raise FileNotFoundError(
                "Model artifacts are missing. Run `python phishguard/train_model.py` first."
            )

        self.model = self._load_artifact(self.model_path)
        self.vectorizer = self._load_artifact(self.vectorizer_path)
        self.model_name = getattr(self.model, "model_name_", self.model.__class__.__name__)
        self.training_samples = getattr(self.model, "training_samples_", None)

    def predict(self, text: str) -> Dict[str, Any]:
        """Predict phishing likelihood for a text payload."""
        cleaned_text = self.preprocess_text(text)
        if not cleaned_text:
            cleaned_text = "empty"

        vectorized = self.vectorizer.transform([cleaned_text])

        classes = list(getattr(self.model, "classes_", [0, 1]))
        phishing_index = classes.index(1) if 1 in classes else len(classes) - 1

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(vectorized)[0]
            phishing_confidence = float(probabilities[phishing_index])
        else:
            prediction = self.model.predict(vectorized)[0]
            phishing_confidence = 1.0 if int(prediction) == 1 else 0.0

        prediction_label = "phishing" if phishing_confidence >= 0.5 else "legitimate"

        return {
            "prediction": prediction_label,
            "confidence": round(phishing_confidence, 4),
            "features_used": "tfidf",
            "model_name": self.model_name,
            "training_samples": self.training_samples,
        }

    @staticmethod
    def preprocess_text(text: str) -> str:
        """Normalize text consistently with training preprocessing."""
        normalized = (text or "").lower()
        normalized = re.sub(r"[^a-z0-9\s:/._-]", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    @staticmethod
    def _load_artifact(path: Path) -> Any:
        """Load persisted model/vectorizer using joblib or pickle."""
        if joblib is not None:
            return joblib.load(path)

        with path.open("rb") as handle:
            return pickle.load(handle)
