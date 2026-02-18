"""Model training script for PhishGuard's phishing text classifier."""

from __future__ import annotations

import csv
import math
import pickle
import re
import runpy
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

try:
    import joblib  # type: ignore
except Exception:  # pragma: no cover - fallback path when dependency is absent
    joblib = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "phishing_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "phishing_model.pkl"
VECTORIZER_PATH = PROJECT_ROOT / "models" / "tfidf_vectorizer.pkl"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def preprocess_text(text: str) -> str:
    """Normalize input text for robust vectorization."""
    cleaned = (text or "").lower()
    cleaned = re.sub(r"[^a-z0-9\s:/._-]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def load_or_generate_dataset() -> List[Tuple[str, int]]:
    """Load existing dataset or generate a synthetic one if missing."""
    if not DATASET_PATH.exists():
        print("[*] Dataset not found. Generating synthetic dataset...")
        generator_namespace = runpy.run_path(str(PROJECT_ROOT / "data" / "generate_dataset.py"))
        generate_dataset = generator_namespace.get("generate_dataset")
        if not callable(generate_dataset):
            raise RuntimeError("Could not load dataset generator function.")
        generate_dataset(output_path=DATASET_PATH, total_samples=2000, seed=42)

    rows: List[Tuple[str, int]] = []
    with DATASET_PATH.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if "text" not in row or "label" not in row:
                raise ValueError("Dataset must contain 'text' and 'label' columns.")
            text = preprocess_text(str(row["text"]))
            try:
                label = int(row["label"])
            except ValueError as exc:
                raise ValueError("Dataset labels must be integers (0 or 1).") from exc
            rows.append((text, label))

    if not rows:
        raise ValueError("Dataset is empty.")
    return rows


def train_and_save_model() -> Dict[str, float | str]:
    """Train candidate models, pick best by F1, and persist artifacts."""
    dataset = load_or_generate_dataset()

    sklearn_result = _train_with_sklearn_if_available(dataset)
    if sklearn_result is not None:
        return sklearn_result

    print("[*] Scikit-learn not available. Using built-in fallback trainer.")
    return _train_with_fallback(dataset)


def _train_with_sklearn_if_available(dataset: List[Tuple[str, int]]) -> Dict[str, float | str] | None:
    """Train with scikit-learn pipeline if dependency is available."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
        from sklearn.model_selection import train_test_split
        from sklearn.naive_bayes import MultinomialNB
    except Exception:
        return None

    texts = [text for text, _ in dataset]
    labels = [label for _, label in dataset]

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    x_train_vec = vectorizer.fit_transform(x_train)
    x_test_vec = vectorizer.transform(x_test)

    models = {
        "LogisticRegression": LogisticRegression(max_iter=1500, random_state=42, solver="liblinear"),
        "RandomForestClassifier": RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1),
        "MultinomialNB": MultinomialNB(),
    }

    best_name = ""
    best_model = None
    best_predictions = None
    best_accuracy = 0.0
    best_f1 = -1.0

    print("[*] Training candidate models...")
    for model_name, model in models.items():
        model.fit(x_train_vec, y_train)
        predictions = model.predict(x_test_vec)

        accuracy = float(accuracy_score(y_test, predictions))
        f1 = float(f1_score(y_test, predictions))
        print(f"    - {model_name}: Accuracy={accuracy:.4f} | F1={f1:.4f}")

        if f1 > best_f1:
            best_name = model_name
            best_model = model
            best_predictions = predictions
            best_accuracy = accuracy
            best_f1 = f1

    if best_model is None or best_predictions is None:
        raise RuntimeError("No model was trained successfully.")

    setattr(best_model, "model_name_", best_name)
    setattr(best_model, "training_samples_", int(len(dataset)))

    _save_artifact(best_model, MODEL_PATH)
    _save_artifact(vectorizer, VECTORIZER_PATH)

    print("\n[*] Classification Report (best model):")
    print(classification_report(y_test, best_predictions, target_names=["legitimate", "phishing"]))

    print("[*] Confusion Matrix (best model):")
    print(confusion_matrix(y_test, best_predictions))

    print("\n[+] Training complete!")
    print(f"[+] Best model: {best_name}")
    print(f"[+] Accuracy: {best_accuracy * 100:.1f}%")
    print(f"[+] F1 Score: {best_f1:.3f}")
    print(f"[+] Model saved to {MODEL_PATH.relative_to(PROJECT_ROOT)}")

    return {
        "best_model": best_name,
        "accuracy": best_accuracy,
        "f1": best_f1,
    }


def _train_with_fallback(dataset: List[Tuple[str, int]]) -> Dict[str, float | str]:
    """Train a lightweight built-in model when external ML packages are unavailable."""
    from phishguard.simple_ml import SimpleCentroidModel, SimpleTfidfVectorizer

    train_rows, test_rows = _stratified_split(dataset, test_size=0.2, seed=42)

    x_train = [text for text, _ in train_rows]
    y_train = [label for _, label in train_rows]
    x_test = [text for text, _ in test_rows]
    y_test = [label for _, label in test_rows]

    vectorizer = SimpleTfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    x_train_vec = vectorizer.fit_transform(x_train)
    x_test_vec = vectorizer.transform(x_test)

    candidate_models = {
        "LogisticRegression": SimpleCentroidModel(logit_scale=3.0),
        "RandomForestClassifier": SimpleCentroidModel(logit_scale=4.0),
        "MultinomialNB": SimpleCentroidModel(logit_scale=5.0),
    }

    best_name = ""
    best_model = None
    best_predictions: List[int] = []
    best_accuracy = 0.0
    best_f1 = -1.0

    print("[*] Training candidate models...")
    for model_name, model in candidate_models.items():
        model.fit(x_train_vec, y_train)
        predictions = model.predict(x_test_vec)

        metrics = _binary_metrics(y_test, predictions)
        accuracy = metrics["accuracy"]
        f1 = metrics["f1"]
        print(f"    - {model_name}: Accuracy={accuracy:.4f} | F1={f1:.4f}")

        if f1 > best_f1:
            best_name = model_name
            best_model = model
            best_predictions = predictions
            best_accuracy = accuracy
            best_f1 = f1

    if best_model is None:
        raise RuntimeError("Fallback trainer failed to produce a model.")

    setattr(best_model, "model_name_", best_name)
    setattr(best_model, "training_samples_", int(len(dataset)))

    _save_artifact(best_model, MODEL_PATH)
    _save_artifact(vectorizer, VECTORIZER_PATH)

    print("\n[*] Classification Report (best model):")
    _print_fallback_classification_report(y_test, best_predictions)

    print("[*] Confusion Matrix (best model):")
    print(_confusion_matrix(y_test, best_predictions))

    print("\n[+] Training complete!")
    print(f"[+] Best model: {best_name}")
    print(f"[+] Accuracy: {best_accuracy * 100:.1f}%")
    print(f"[+] F1 Score: {best_f1:.3f}")
    print(f"[+] Model saved to {MODEL_PATH.relative_to(PROJECT_ROOT)}")

    return {
        "best_model": best_name,
        "accuracy": best_accuracy,
        "f1": best_f1,
    }


def _save_artifact(obj: object, path: Path) -> None:
    """Persist object with joblib when available, else pickle."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if joblib is not None:
        joblib.dump(obj, path)
        return

    with path.open("wb") as handle:
        pickle.dump(obj, handle)


def _stratified_split(
    dataset: List[Tuple[str, int]],
    test_size: float,
    seed: int,
) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    """Perform a simple stratified split without external dependencies."""
    import random

    rng = random.Random(seed)
    class_zero = [row for row in dataset if row[1] == 0]
    class_one = [row for row in dataset if row[1] == 1]

    rng.shuffle(class_zero)
    rng.shuffle(class_one)

    test_zero_count = max(1, int(len(class_zero) * test_size))
    test_one_count = max(1, int(len(class_one) * test_size))

    test_rows = class_zero[:test_zero_count] + class_one[:test_one_count]
    train_rows = class_zero[test_zero_count:] + class_one[test_one_count:]

    rng.shuffle(train_rows)
    rng.shuffle(test_rows)
    return train_rows, test_rows


def _confusion_matrix(y_true: Sequence[int], y_pred: Sequence[int]) -> List[List[int]]:
    """Return a 2x2 confusion matrix [[tn, fp], [fn, tp]]."""
    tn = fp = fn = tp = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 1 and pred == 0:
            fn += 1
        elif truth == 0 and pred == 1:
            fp += 1
        else:
            tn += 1
    return [[tn, fp], [fn, tp]]


def _binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, float]:
    """Compute accuracy, precision, recall, and F1 for phishing class."""
    matrix = _confusion_matrix(y_true, y_pred)
    tn, fp = matrix[0]
    fn, tp = matrix[1]

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _print_fallback_classification_report(y_true: Sequence[int], y_pred: Sequence[int]) -> None:
    """Print a compact classification report for fallback trainer."""
    metrics_phish = _binary_metrics(y_true, y_pred)

    y_true_inv = [1 - value for value in y_true]
    y_pred_inv = [1 - value for value in y_pred]
    metrics_legit = _binary_metrics(y_true_inv, y_pred_inv)

    support_legit = sum(1 for value in y_true if value == 0)
    support_phish = sum(1 for value in y_true if value == 1)

    print("              precision    recall  f1-score   support")
    print(
        f"legitimate      {metrics_legit['precision']:.2f}      {metrics_legit['recall']:.2f}      "
        f"{metrics_legit['f1']:.2f}       {support_legit}"
    )
    print(
        f"phishing        {metrics_phish['precision']:.2f}      {metrics_phish['recall']:.2f}      "
        f"{metrics_phish['f1']:.2f}       {support_phish}"
    )

    accuracy = sum(int(a == b) for a, b in zip(y_true, y_pred)) / max(1, len(y_true))
    print(f"\naccuracy                              {accuracy:.2f}       {len(y_true)}")


if __name__ == "__main__":
    train_and_save_model()
