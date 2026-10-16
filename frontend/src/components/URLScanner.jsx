import { useState } from "react";

function URLScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleScan(event) {
    event.preventDefault();

    const trimmedURL = url.trim();

    if (!trimmedURL) {
      setError("Please enter a URL to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/scan/url",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: trimmedURL,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "URL scanning failed."
        );
      }

      setResult(data);
      const previousHistory = JSON.parse(
  localStorage.getItem("scamshield-history") || "[]"
);

const updatedHistory = [
  {
    id: Date.now(),
    type: "URL",
    input: trimmedURL,
    result: data.is_phishing ? "Potential Risk" : "Unconfirmed",
    time: new Date().toLocaleString(),
  },
  ...previousHistory,
].slice(0, 10);

localStorage.setItem(
  "scamshield-history",
  JSON.stringify(updatedHistory)
);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot connect to ScamShield AI. Check whether the backend is running."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  function clearScanner() {
    setUrl("");
    setResult(null);
    setError("");
  }

  const isPhishing = result?.is_phishing === true;

  return (
    <main className="url-scanner-page">
      <section className="url-scanner-heading">
        <p className="eyebrow">AI-POWERED URL ANALYSIS</p>

        <h1>Check a suspicious link.</h1>

        <p>
          Analyze URL patterns with the ScamShield AI machine-learning
          model before deciding whether to trust a link.
        </p>
      </section>

      <section className="url-scanner-card">
        <div className="url-scanner-title">
          <div>
            <h2>URL Scanner</h2>
            <p>Enter the complete URL you want to analyze.</p>
          </div>

          <span className="model-badge">URL Classifier</span>
        </div>

        <form onSubmit={handleScan}>
          <label htmlFor="url-input">Website URL</label>

          <input
            id="url-input"
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            maxLength={2048}
            autoComplete="url"
            spellCheck={false}
          />

          <div className="url-input-footer">
            <span>Maximum 2048 characters</span>

            <button
              type="button"
              className="clear-button"
              onClick={clearScanner}
            >
              Clear
            </button>
          </div>

          <button
            className="scan-button"
            type="submit"
            disabled={loading || !url.trim()}
          >
            {loading ? "Analyzing URL..." : "🛡️ Scan URL"}
          </button>
        </form>

        {error && (
          <div className="error-box" role="alert">
            <strong>Scan unsuccessful</strong>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <section
            className={`result-card ${
              isPhishing ? "result-danger" : "result-safe"
            }`}
            aria-live="polite"
          >
            <div className="result-header">
              <div>
                <p className="result-label">SCAN RESULT</p>

                <h3>
                  {isPhishing
                    ? "Potential Phishing URL"
                    : "Not Classified as Phishing"}
                </h3>
              </div>

              <span className="risk-badge">
                {result.risk_level || "Unconfirmed"}
              </span>
            </div>

            <p>{result.explanation}</p>

            <div className="url-result-details">
              <span>Analyzed URL</span>
              <strong>{result.url}</strong>
            </div>

            {Array.isArray(result.recommendations) &&
              result.recommendations.length > 0 && (
                <div className="recommendation-section">
                  <h4>🛡️ Recommended Actions</h4>

                  <ul>
                    {result.recommendations.map((recommendation, index) => (
                      <li key={index}>{recommendation}</li>
                    ))}
                  </ul>
                </div>
              )}

            <div className="url-result-details">
              <span>Model</span>
              <strong>{result.model || "URL Classifier"}</strong>
            </div>

            <p className="safety-notice">
              {result.warning ||
                "This is an experimental ML prediction, not a guarantee. The URL has not been independently verified."}
            </p>
          </section>
        )}

        <div className="url-scanner-note">
          <strong>Privacy and safety</strong>
          <p>
            ScamShield AI analyzes URL features without opening the
            submitted website. A URL classified as legitimate may still
            be malicious, so verify unexpected links independently.
          </p>
        </div>
      </section>
    </main>
  );
}

export default URLScanner;