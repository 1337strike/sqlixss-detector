"""
features.py
------------
TF-IDF feature extraction wrapper (Chapter 3, Section 3.5 / Module 3).

We wrap scikit-learn's TfidfVectorizer with our custom tokenizer so the
vocabulary is built from SQLi/XSS-aware tokens (', =, <, >, /, --, etc.)
instead of being split on whitespace like ordinary natural-language text.
"""

from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer

from src.tokenizer import tokenize


def build_vectorizer(max_features: int = 4000, ngram_range: tuple[int, int] = (1, 2)) -> TfidfVectorizer:
    """
    max_features : cap on vocabulary size, keeps the feature matrix (and
                   therefore inference latency) bounded even if the corpus
                   grows a lot -- important for the "lightweight" claim.
    ngram_range  : (1, 2) means unigrams AND bigrams of tokens are used,
                   e.g. the bigram ("1", "=") captures "1=1" as a single
                   feature in addition to "1" and "=" individually.
    """
    return TfidfVectorizer(
        tokenizer=tokenize,
        token_pattern=None,   # required by sklearn when a custom tokenizer is supplied
        lowercase=False,       # tokenizer already handles case normalization for words
        max_features=max_features,
        ngram_range=ngram_range,
        sublinear_tf=True,     # log-scaled term frequency, standard TF-IDF refinement
    )


if __name__ == "__main__":
    samples = [
        "id=5&sort=asc",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
    ]
    vec = build_vectorizer(max_features=50)
    X = vec.fit_transform(samples)
    print("Vocabulary size:", len(vec.vocabulary_))
    print("Feature matrix shape:", X.shape)
    print("Sample vocabulary:", list(vec.vocabulary_.items())[:15])
