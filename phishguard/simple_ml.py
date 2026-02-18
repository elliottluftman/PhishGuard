"""Lightweight fallback ML components for offline PhishGuard usage."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List


def _tokenize(text: str, ngram_range: tuple[int, int]) -> List[str]:
    """Tokenize text into unigrams/bigrams using simple alphanumeric tokenization."""
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    if not words:
        return []

    tokens: List[str] = []
    min_n, max_n = ngram_range
    for n in range(min_n, max_n + 1):
        if n == 1:
            tokens.extend(words)
            continue
        for index in range(len(words) - n + 1):
            tokens.append(" ".join(words[index : index + n]))
    return tokens


class SimpleTfidfVectorizer:
    """A compact TF-IDF vectorizer with a scikit-learn-like interface."""

    def __init__(self, max_features: int = 10000, ngram_range: tuple[int, int] = (1, 2)) -> None:
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: Dict[str, float] = {}

    def fit(self, texts: Iterable[str]) -> "SimpleTfidfVectorizer":
        """Learn vocabulary and IDF weights from training data."""
        document_frequency: Counter[str] = Counter()
        term_frequency: Counter[str] = Counter()
        document_count = 0

        for text in texts:
            tokens = _tokenize(text, self.ngram_range)
            if not tokens:
                continue
            document_count += 1
            token_counts = Counter(tokens)
            term_frequency.update(token_counts)
            document_frequency.update(token_counts.keys())

        if not term_frequency:
            self.vocabulary_ = {}
            self.idf_ = {}
            return self

        most_common = term_frequency.most_common(self.max_features)
        self.vocabulary_ = {token: idx for idx, (token, _) in enumerate(most_common)}

        self.idf_ = {}
        for token in self.vocabulary_:
            df = document_frequency.get(token, 1)
            self.idf_[token] = math.log((1 + document_count) / (1 + df)) + 1.0

        return self

    def transform(self, texts: Iterable[str]) -> List[Dict[int, float]]:
        """Convert raw texts into sparse TF-IDF vectors."""
        vectors: List[Dict[int, float]] = []
        for text in texts:
            token_counts = Counter(_tokenize(text, self.ngram_range))
            if not token_counts:
                vectors.append({})
                continue

            total_terms = sum(token_counts.values())
            sparse_vector: Dict[int, float] = {}
            for token, count in token_counts.items():
                if token not in self.vocabulary_:
                    continue
                idx = self.vocabulary_[token]
                tf = count / total_terms
                idf = self.idf_.get(token, 1.0)
                sparse_vector[idx] = tf * idf
            vectors.append(sparse_vector)
        return vectors

    def fit_transform(self, texts: Iterable[str]) -> List[Dict[int, float]]:
        """Learn vocabulary and transform in one pass."""
        text_list = list(texts)
        self.fit(text_list)
        return self.transform(text_list)


class SimpleCentroidModel:
    """Centroid similarity classifier with probabilistic phishing output."""

    def __init__(self, logit_scale: float = 4.0) -> None:
        self.logit_scale = logit_scale
        self.classes_ = [0, 1]
        self._centroids: Dict[int, Dict[int, float]] = {0: {}, 1: {}}
        self._norms: Dict[int, float] = {0: 1.0, 1: 1.0}

    def fit(self, vectors: List[Dict[int, float]], labels: List[int]) -> "SimpleCentroidModel":
        """Fit class centroids from sparse TF-IDF vectors."""
        sums = {0: defaultdict(float), 1: defaultdict(float)}
        counts = {0: 0, 1: 0}

        for vector, label in zip(vectors, labels):
            class_label = int(label)
            counts[class_label] += 1
            for idx, value in vector.items():
                sums[class_label][idx] += value

        centroids: Dict[int, Dict[int, float]] = {0: {}, 1: {}}
        for class_label in (0, 1):
            divisor = max(1, counts[class_label])
            centroids[class_label] = {
                idx: value / divisor
                for idx, value in sums[class_label].items()
            }

        self._centroids = centroids
        self._norms = {
            class_label: math.sqrt(sum(value * value for value in centroid.values())) or 1.0
            for class_label, centroid in centroids.items()
        }
        return self

    def predict_proba(self, vectors: List[Dict[int, float]]) -> List[List[float]]:
        """Predict class probabilities for sparse vectors."""
        probabilities: List[List[float]] = []

        for vector in vectors:
            sim_legit = self._cosine_similarity(vector, self._centroids[0], self._norms[0])
            sim_phish = self._cosine_similarity(vector, self._centroids[1], self._norms[1])
            score = (sim_phish - sim_legit) * self.logit_scale
            phishing_prob = 1.0 / (1.0 + math.exp(-score))
            probabilities.append([1.0 - phishing_prob, phishing_prob])

        return probabilities

    def predict(self, vectors: List[Dict[int, float]]) -> List[int]:
        """Predict class labels using 0.5 phishing-probability threshold."""
        return [1 if row[1] >= 0.5 else 0 for row in self.predict_proba(vectors)]

    @staticmethod
    def _cosine_similarity(
        vector: Dict[int, float],
        centroid: Dict[int, float],
        centroid_norm: float,
    ) -> float:
        """Compute cosine similarity between sparse vectors."""
        if not vector:
            return 0.0

        dot = 0.0
        vector_norm_sq = 0.0

        for idx, value in vector.items():
            vector_norm_sq += value * value
            dot += value * centroid.get(idx, 0.0)

        vector_norm = math.sqrt(vector_norm_sq) or 1.0
        return dot / (vector_norm * centroid_norm)
