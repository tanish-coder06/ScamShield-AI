from pathlib import Path
import json

import joblib
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

DATASET_NAME = "sidzzz07/scamshield-dataset"

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"

TEXT_COLUMN = "text"
LABEL_COLUMN = "is_scam"


def evaluate_model(model, texts, labels):
    """Calculate classification metrics."""

    predictions = model.predict(texts)

    return {
        "accuracy": round(
            accuracy_score(labels, predictions), 4
        ),
        "precision": round(
            precision_score(labels, predictions, zero_division=0), 4
        ),
        "recall": round(
            recall_score(labels, predictions, zero_division=0), 4
        ),
        "f1_score": round(
            f1_score(labels, predictions, zero_division=0), 4
        ),
        "confusion_matrix": confusion_matrix(
            labels, predictions, labels=[0, 1]
        ).tolist(),
    }


def main():
    print("=" * 60)
    print("        ScamShield AI - Message Model Training")
    print("=" * 60)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load the dataset
    print("\n[1/5] Loading dataset...")

    dataset = load_dataset(DATASET_NAME)

    for required_split in ["train", "validation", "test"]:
        if required_split not in dataset:
            raise ValueError(
                f"Required dataset split missing: {required_split}"
            )

    train_data = dataset["train"]
    validation_data = dataset["validation"]
    test_data = dataset["test"]

    required_columns = {TEXT_COLUMN, LABEL_COLUMN}

    if not required_columns.issubset(train_data.column_names):
        raise ValueError(
            f"Expected columns {required_columns}, "
            f"but found {train_data.column_names}"
        )

    # 2. Prepare text and labels
    print("\n[2/5] Preparing training data...")

    def prepare_split(split):
        texts = []
        labels = []

        for row in split:
            text = row[TEXT_COLUMN]
            label = row[LABEL_COLUMN]

            if text is None or not str(text).strip():
                continue

            if label is None:
                continue

            label = int(label)

            if label not in (0, 1):
                raise ValueError(
                    f"Unexpected label: {label}"
                )

            texts.append(str(text))
            labels.append(label)

        return texts, labels

    X_train, y_train = prepare_split(train_data)
    X_val, y_val = prepare_split(validation_data)
    X_test, y_test = prepare_split(test_data)

    print(f"Training examples:   {len(X_train)}")
    print(f"Validation examples: {len(X_val)}")
    print(f"Test examples:       {len(X_test)}")

    print(f"Training scam examples: {sum(y_train)}")
    print(
        f"Training legitimate examples: "
        f"{len(y_train) - sum(y_train)}"
    )

    # 3. Define candidate algorithms
    print("\n[3/5] Training three algorithms...")

    algorithms = {
        "Naive Bayes": MultinomialNB(),

        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),

        "Linear SVM": LinearSVC(
            class_weight="balanced",
            random_state=42,
        ),
    }

    results = {}
    trained_models = {}

    for name, classifier in algorithms.items():
        print(f"\nTraining: {name}")

        model = Pipeline([
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    max_features=100_000,
                    sublinear_tf=True,
                ),
            ),
            ("classifier", classifier),
        ])

        model.fit(X_train, y_train)

        # Use validation data to compare models.
        metrics = evaluate_model(model, X_val, y_val)

        results[name] = metrics
        trained_models[name] = model

        print(f"Accuracy:  {metrics['accuracy']}")
        print(f"Precision: {metrics['precision']}")
        print(f"Recall:    {metrics['recall']}")
        print(f"F1-score:  {metrics['f1_score']}")
        print(f"Confusion matrix: {metrics['confusion_matrix']}")

    # 4. Select model based on validation F1
    print("\n[4/5] Selecting the best validation model...")

    best_name = max(
        results,
        key=lambda name: results[name]["f1_score"],
    )

    best_model = trained_models[best_name]

    print(f"Selected model: {best_name}")

    # 5. Evaluate the selected model on the untouched test set
    print("\n[5/5] Final test-set evaluation...")

    test_metrics = evaluate_model(best_model, X_test, y_test)

    print("\nFinal test metrics:")
    print(json.dumps(test_metrics, indent=2))

    print("\nDetailed classification report:")
    print(
        classification_report(
            y_test,
            best_model.predict(X_test),
            labels=[0, 1],
            target_names=["Legitimate", "Scam"],
            zero_division=0,
        )
    )

    # Save model and metadata
    model_path = MODEL_DIR / "message_model.joblib"
    metadata_path = MODEL_DIR / "message_model_metrics.json"

    joblib.dump(best_model, model_path)

    metadata = {
        "dataset": DATASET_NAME,
        "selected_algorithm": best_name,
        "validation_results": results,
        "test_results": test_metrics,
        "label_mapping": {
            "0": "legitimate",
            "1": "scam",
        },
    }

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print(f"\nModel saved to: {model_path}")
    print(f"Metrics saved to: {metadata_path}")
    print("\nMessage model training completed successfully!")


if __name__ == "__main__":
    main()