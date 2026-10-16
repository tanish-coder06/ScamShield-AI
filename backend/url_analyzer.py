from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json

import joblib
import pandas as pd

from ucimlrepo import fetch_ucirepo

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"

MODEL_PATH = MODEL_DIR / "url_model.joblib"
METRICS_PATH = MODEL_DIR / "url_model_metrics.json"

DATASET_ID = 967

LEGITIMATE_LABEL = 1
PHISHING_LABEL = 0

FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfOtherSpecialCharsInURL",
    "LetterRatioInURL",
    "DegitRatioInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


# ============================================================
# URL VALIDATION
# ============================================================

def normalize_url(url: str) -> str:
    """Validate and normalize a URL without visiting it."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a URL.")

    url = url.strip()

    if any(character.isspace() for character in url):
        raise ValueError(
            "The URL must not contain whitespace."
        )

    candidate = url if "://" in url else "//" + url

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("Please enter a valid URL.") from error

    if not hostname:
        raise ValueError(
            "Enter a complete URL, such as https://example.com."
        )

    if parsed.scheme and parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    # Reject missing or invalid ports.
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Please enter a valid port.")

    # Reject obvious non-web input.
    if not hostname or hostname.startswith("."):
        raise ValueError("Please enter a valid hostname.")

    return url


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_url_features(url: str) -> dict:
    """
    Extract approximate URL-string features.

    This function does not visit the URL.
    It is used for both training and inference.
    """

    url = normalize_url(url)

    candidate = url if "://" in url else "//" + url
    parsed = urlsplit(candidate)

    hostname = parsed.hostname.lower()

    url_length = len(url)
    domain_length = len(hostname)

    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # Approximate subdomain count.
    # This is not a Public Suffix List-based calculation.
    if is_domain_ip:
        no_subdomains = 0
    else:
        labels = hostname.rstrip(".").split(".")
        no_subdomains = max(0, len(labels) - 2)

    letters = sum(character.isalpha() for character in url)
    digits = sum(character.isdigit() for character in url)

    special_chars = sum(
        not character.isalnum()
        for character in url
    )

    safe_length = max(url_length, 1)

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "NoOfSubDomain": no_subdomains,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfOtherSpecialCharsInURL": special_chars,
        "LetterRatioInURL": letters / safe_length,
        "DegitRatioInURL": digits / safe_length,
        "SpacialCharRatioInURL": special_chars / safe_length,
        "IsHTTPS": int(parsed.scheme.lower() == "https"),
    }


def features_from_url_series(urls: pd.Series) -> pd.DataFrame:
    """Extract the same features from every training URL."""

    records = []

    for index, url in urls.items():
        try:
            records.append(extract_url_features(str(url)))
        except ValueError as error:
            raise ValueError(
                f"Invalid URL in dataset at row {index}: {error}"
            ) from error

    return pd.DataFrame(
        records,
        columns=FEATURE_COLUMNS,
        index=urls.index,
    )


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(model, X, y):
    """
    Phishing is the positive class.

    Confusion matrix:
        [[TN, FP],
         [FN, TP]]
    """

    predictions = model.predict(X)

    matrix = confusion_matrix(
        y,
        predictions,
        labels=[LEGITIMATE_LABEL, PHISHING_LABEL],
    )

    tn, fp, fn, tp = matrix.ravel()

    return {
        "accuracy": round(accuracy_score(y, predictions), 4),
        "precision": round(
            precision_score(
                y,
                predictions,
                pos_label=PHISHING_LABEL,
                zero_division=0,
            ),
            4,
        ),
        "recall": round(
            recall_score(
                y,
                predictions,
                pos_label=PHISHING_LABEL,
                zero_division=0,
            ),
            4,
        ),
        "f1_score": round(
            f1_score(
                y,
                predictions,
                pos_label=PHISHING_LABEL,
                zero_division=0,
            ),
            4,
        ),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "confusion_matrix": matrix.tolist(),
    }


# ============================================================
# TRAINING
# ============================================================

def main():
    print("=" * 65)
    print("ScamShield AI - URL Model Training")
    print("=" * 65)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load dataset.
    print("\n[1/6] Loading UCI dataset...")

    dataset = fetch_ucirepo(id=DATASET_ID)

    raw_features = dataset.data.features
    targets = dataset.data.targets

    if "URL" not in raw_features.columns:
        raise ValueError("The dataset does not contain a URL column.")

    if "label" not in targets.columns:
        raise ValueError("The dataset does not contain a label column.")

    urls = raw_features["URL"].reset_index(drop=True)
    labels = targets["label"].reset_index(drop=True)

    valid = urls.notna() & labels.notna()

    urls = urls[valid].reset_index(drop=True)
    labels = labels[valid].astype(int).reset_index(drop=True)

    if set(labels.unique()) != {0, 1}:
        raise ValueError(
            "Expected dataset labels 0 and 1."
        )

    print("Usable records:", len(urls))
    print("Label counts:")
    print(labels.value_counts().sort_index())
    print("\nChecking example domains in the dataset:")

    mask = urls.astype(str).str.contains(
    r"example\.(com|org|net)",
    case=False,
    regex=True,
    na=False,
)

    if mask.any():
        print(pd.DataFrame({
        "URL": urls[mask],
        "Label": labels[mask],
    }).head(20).to_string(index=False))
    else:
        print("No example.com/org/net URLs found in the dataset.")
    print("\nSample URLs by label:")

    for label in sorted(labels.unique()):
        print(f"\nLabel {label} examples:")
        print(urls[labels == label].head(10).to_string(index=False))

    # 2. Extract features using the same function used by prediction.
    print("\n[2/6] Extracting features from raw URLs...")
    print("This may take several minutes.")

    X = features_from_url_series(urls)

    print("Feature matrix shape:", X.shape)
    print(X.head())

    # 3. Create train, validation, and test splits.
    print("\n[3/6] Creating data splits...")

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        labels,
        test_size=0.30,
        random_state=42,
        stratify=labels,
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp,
    )

    print("Training records:", len(X_train))
    print("Validation records:", len(X_val))
    print("Test records:", len(X_test))

    # 4. Train and evaluate three algorithms.
    print("\n[4/6] Training models...")

    algorithms = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=20,
            class_weight="balanced",
            random_state=42,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
    }

    trained_models = {}
    validation_results = {}

    for name, classifier in algorithms.items():
        print(f"\nTraining {name}...")

        steps = [
            ("imputer", SimpleImputer(strategy="median"))
        ]

        if name == "Logistic Regression":
            steps.append(("scaler", StandardScaler()))

        steps.append(("classifier", classifier))

        model = Pipeline(steps)
        model.fit(X_train, y_train)

        metrics = evaluate_model(model, X_val, y_val)

        trained_models[name] = model
        validation_results[name] = metrics

        print(json.dumps(metrics, indent=2))

    # 5. Select the best model using validation F1-score.
    print("\n[5/6] Selecting the best model...")

    best_name = max(
        validation_results,
        key=lambda name: validation_results[name]["f1_score"],
    )

    best_model = trained_models[best_name]

    print("Selected model:", best_name)

    # Test the selected model only after selection.
    test_metrics = evaluate_model(best_model, X_test, y_test)

    print("\nFinal test metrics:")
    print(json.dumps(test_metrics, indent=2))

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            best_model.predict(X_test),
            labels=[LEGITIMATE_LABEL, PHISHING_LABEL],
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    # 6. Save model and metrics.
    print("\n[6/6] Saving model...")

    joblib.dump(best_model, MODEL_PATH)

    metadata = {
        "dataset": "UCI PhiUSIIL Phishing URL Dataset",
        "dataset_id": DATASET_ID,
        "selected_algorithm": best_name,
        "feature_columns": FEATURE_COLUMNS,
        "validation_results": validation_results,
        "test_results": test_metrics,
        "split_sizes": {
            "train": len(X_train),
            "validation": len(X_val),
            "test": len(X_test),
        },
        "limitations": [
            "Features are approximate URL-string heuristics.",
            "Training and inference use the same feature extractor.",
            "Random splitting may overestimate performance on unseen domains.",
            "Predictions do not guarantee that a URL is safe or malicious.",
        ],
    }

    METRICS_PATH.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("\nSaved model:", MODEL_PATH)
    print("Saved metrics:", METRICS_PATH)
    print("\nTraining complete!")


# ============================================================
# PREDICTION
# ============================================================

def predict_url(url: str) -> dict:
    """Predict phishing patterns without opening the URL."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "URL model is missing. Run python url_analyzer.py first."
        )

    row = pd.DataFrame(
        [extract_url_features(url)],
        columns=FEATURE_COLUMNS,
    )

    model = joblib.load(MODEL_PATH)

    prediction = int(model.predict(row)[0])
    is_phishing = prediction == PHISHING_LABEL

    if is_phishing:
        risk_level = "Potential Risk"
        explanation = (
            "The experimental model detected URL patterns associated "
            "with phishing. This result may be a false positive and "
            "does not confirm that the website is malicious."
        )
        recommendations = [
            "Avoid opening the link until its destination is verified.",
            "Visit the organization through its official website or app.",
            "Never provide passwords, OTPs, or banking details to an unverified site.",
        ]
    else:
        risk_level = "Unconfirmed"
        explanation = (
            "The model did not classify this URL as phishing. "
            "That does not establish that it is safe."
        )
        recommendations = [
            "Check the spelling of the domain.",
            "Be cautious of unexpected requests for money or sensitive information.",
            "Verify the destination independently before signing in.",
        ]

    return {
        "input_type": "url",
        "url": url,
        "prediction": (
            "phishing" if is_phishing else "not_classified_as_phishing"
        ),
        "is_phishing": is_phishing,
        "risk_level": risk_level,
        "explanation": explanation,
        "recommendations": recommendations,
        "model": "URL classifier",
        "warning": (
            "Experimental ML prediction only. The URL was not visited "
            "or independently checked. A prediction is not a safety guarantee."
        ),
    }


# ============================================================
# DIAGNOSTICS
# ============================================================

def inspect_training_feature_ranges():
    print("\n" + "=" * 65)
    print("TRAINING FEATURE RANGE ANALYSIS")
    print("=" * 65)

    dataset = fetch_ucirepo(id=DATASET_ID)

    raw_features = dataset.data.features
    targets = dataset.data.targets

    urls = raw_features["URL"].reset_index(drop=True)
    labels = targets["label"].reset_index(drop=True).astype(int)

    valid = urls.notna() & labels.notna()

    urls = urls[valid].reset_index(drop=True)
    labels = labels[valid].reset_index(drop=True)

    sample_size = min(10000, len(urls))

    sample_indices = urls.sample(
        n=sample_size,
        random_state=42,
    ).index

    sample_urls = urls.loc[sample_indices].reset_index(drop=True)
    sample_labels = labels.loc[sample_indices].reset_index(drop=True)

    X_sample = features_from_url_series(sample_urls)

    print("\nFeature ranges by label:")
    print(
        X_sample.assign(label=sample_labels)
        .groupby("label")[FEATURE_COLUMNS]
        .agg(["min", "median", "max"])
        .to_string()
    )

    print("\nLive URL features:")

    for url in [
        "https://www.google.com",
        "https://example.com",
        "http://example.com",
    ]:
        print(f"\nURL: {url}")
        print(json.dumps(extract_url_features(url), indent=2))


def diagnose_url_model():
    print("\n" + "=" * 65)
    print("URL MODEL SANITY CHECK")
    print("=" * 65)

    # Check whether the saved model exists.
    if not MODEL_PATH.exists():
        print("Model file is missing. Train the model first.")
        return

    # Load the saved model.
    model = joblib.load(MODEL_PATH)

    # Test URLs.
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://example.com",
        "https://example.org",
        "https://example.net",
        "https://www.iana.org",
    ]

    # Get the final classifier from the pipeline.
    classifier = model.named_steps["classifier"]

    # Display feature importance when supported.
    if hasattr(classifier, "feature_importances_"):
        importance = pd.Series(
            classifier.feature_importances_,
            index=FEATURE_COLUMNS,
        ).sort_values(ascending=False)

        print("\nTop model features:")
        print(importance.head(10).to_string())

        print("\nModel feature importance (all features):")
        print(importance.to_string())

    # Test each URL.
    for url in test_urls:
        row = pd.DataFrame(
            [extract_url_features(url)],
            columns=FEATURE_COLUMNS,
        )

        # Predict the class.
        prediction = int(model.predict(row)[0])

        # Print a separator and URL.
        print("\n" + "-" * 60)
        print("URL:", url)

        # Display extracted features.
        print("\nExtracted features:")
        print(json.dumps(row.iloc[0].to_dict(), indent=2))

        # Display predicted class and available classes.
        print("\nModel classes:", model.classes_)
        print("Predicted class:", prediction)

        # Display prediction label.
        if prediction == PHISHING_LABEL:
            print("Prediction: PHISHING")
        else:
            print("Prediction: NOT CLASSIFIED AS PHISHING")

        # Display probabilities using the correct class mapping.
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(row)[0]

            class_probabilities = {
                int(label): float(probability)
                for label, probability in zip(
                    model.classes_,
                    probabilities,
                )
            }

            print("\nClass probabilities:")

            print(
                f"  PHISHING: "
                f"{class_probabilities.get(PHISHING_LABEL, 0.0):.4f}"
            )

            print(
                f"  LEGITIMATE: "
                f"{class_probabilities.get(LEGITIMATE_LABEL, 0.0):.4f}"
            )

    print("\n" + "=" * 65)
    print("DIAGNOSTICS COMPLETE")
    print("=" * 65)
    
if __name__ == "__main__":
    diagnose_url_model()


