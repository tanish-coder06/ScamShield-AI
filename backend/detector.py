from pathlib import Path

import joblib


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "message_model.joblib"

# Load the trained model once when the module is imported.
if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Trained message model not found at: {MODEL_PATH}. "
        "Run train_model.py first."
    )

message_model = joblib.load(MODEL_PATH)


def detect_message(message: str) -> dict:
    """
    Predict whether a message is a scam or legitimate.
    """

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please provide a non-empty message.")

    # Predict class: 0 = legitimate, 1 = scam.
    prediction = int(message_model.predict([message])[0])

    # Get the model's decision score when supported.
    classifier = message_model.named_steps["classifier"]

    decision_score = None

    if hasattr(classifier, "decision_function"):
        decision_score = float(
            message_model.decision_function([message])[0]
        )

    if prediction == 1:
        label = "scam"
        risk_level = "High"
        explanation = "The message resembles scam messages in the training data."
    else:
        label = "legitimate"
        risk_level = "Low"
        explanation = "The model classified this message as legitimate."

    return {
        "prediction": label,
        "is_scam": bool(prediction),
        "risk_level": risk_level,
        "explanation": explanation,
        "model": "Linear SVM",
        "decision_score": decision_score,
    }