from explanations import generate_explanation
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from url_analyzer import predict_url

from detector import detect_message


app = FastAPI(
    title="ScamShield AI",
    description="AI-powered scam and phishing detection API",
    version="1.0.0",
)


# Allow requests from the local React frontend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class MessageScanRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=10000,
        description="Message to scan for potential scams",
    )


@app.get("/")
def home():
    return {
        "message": "Welcome to ScamShield AI",
        "status": "running",
    }


@app.get("/health")
def health():
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent

    message_model_path = base_dir / "model" / "message_model.joblib"
    url_model_path = base_dir / "model" / "url_model.joblib"

    return {
        "status": "healthy",
        "service": "ScamShield AI API",
        "message_model": (
            "loaded" if message_model_path.exists() else "missing"
        ),
        "url_model": (
            "loaded" if url_model_path.exists() else "missing"
        ),
    }


@app.post("/scan/message")
def scan_message(request: MessageScanRequest):
    content = request.content.strip()

    if not content:
        raise HTTPException(
            status_code=422,
            detail="Please enter a message to scan.",
        )

    try:
        result = detect_message(content)

        explanation = generate_explanation(
            message=content,
            is_scam=result["is_scam"],
        )

        return {
            "input_type": "message",
            "scanned_text": content,
            **result,
            **explanation,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:
        print(f"Message scanning error: {error}")

        raise HTTPException(
            status_code=500,
            detail="Message scanning failed. Please try again.",
        ) from error

class URLScanRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL to analyze",
    )


@app.post("/scan/url")
def scan_url(request: URLScanRequest):
    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=422,
            detail="Please enter a URL to scan.",
        )

    try:
        result = predict_url(url)

        return {
            "input_type": "url",
            **result,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail="URL detection model is not available.",
        ) from error

    except Exception as error:
        print(f"URL scanning error: {error}")

        raise HTTPException(
            status_code=500,
            detail="URL scanning failed. Please try again.",
        ) from error