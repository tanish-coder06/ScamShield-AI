import { useState } from "react";
import { useEffect } from "react";
import URLScanner from "./components/URLScanner";
import "./App.css";

function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeScanner, setActiveScanner] = useState("dashboard");
  const [scanHistory, setScanHistory] = useState(() => {
  try {
    return JSON.parse(localStorage.getItem("scamshield-history")) || [];
  } catch {
    return [];
  }
});

  // Switch between dashboard and scanners.
  function switchScanner(scanner) {
    setActiveScanner(scanner);
    setError("");
    setResult(null);
  }

  // Scan a message using the FastAPI backend.
  async function handleScan(event) {
    event.preventDefault();

    if (!message.trim()) {
      setError("Please enter a message to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/scan/message",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content: message.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Message scanning failed."
        );
      }

      setResult(data);
      setScanHistory((previous) => {
  const updated = [
    {
      id: Date.now(),
      type: "Message",
      input: message,
      result: data.is_phishing ? "Potential Risk" : "Unconfirmed",
      time: new Date().toLocaleString(),
    },
    ...previous,
  ].slice(0, 10);

  localStorage.setItem("scamshield-history", JSON.stringify(updated));
  return updated;
});
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot connect to ScamShield AI. Make sure the backend is running."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="navbar">
        <div className="brand">
          <span className="brand-icon">🛡️</span>
          <span>ScamShield AI</span>
        </div>

        <div className="api-status">
          <span className="status-dot"></span>
          AI-Powered Protection
        </div>
      </header>

      <main className="main-content">
        {/* Hero section */}
        <section className="hero">
          <p className="eyebrow">AI-POWERED CYBERSECURITY</p>

          <h1>
            Stay one step ahead of
            <span> digital scams.</span>
          </h1>

          <p className="hero-description">
            Analyze suspicious messages and URLs with machine-learning
            models to identify potential scam indicators.
          </p>
        </section>

        {/* Main navigation */}
        <nav
          className="scanner-navigation"
          aria-label="Main navigation"
        >
          <button
            type="button"
            className={`scanner-nav-button ${
              activeScanner === "dashboard" ? "active" : ""
            }`}
            onClick={() => switchScanner("dashboard")}
            aria-pressed={activeScanner === "dashboard"}
          >
            📊 Dashboard
          </button>

          <button
            type="button"
            className={`scanner-nav-button ${
              activeScanner === "message" ? "active" : ""
            }`}
            onClick={() => switchScanner("message")}
            aria-pressed={activeScanner === "message"}
          >
            💬 Message Scanner
          </button>

          <button
            type="button"
            className={`scanner-nav-button ${
              activeScanner === "url" ? "active" : ""
            }`}
            onClick={() => switchScanner("url")}
            aria-pressed={activeScanner === "url"}
          >
            🔗 URL Scanner
          </button>
        </nav>

        {/* ================================== */}
        {/* DASHBOARD                          */}
        {/* ================================== */}

        {activeScanner === "dashboard" && (
          <>
          <section className="dashboard">
            <div className="scanner-card">
              <div className="section-heading">
                <div>
                  <h2>Security Dashboard</h2>
                  <p>
                    Your AI-assisted scam detection overview.
                  </p>
                </div>

                <span className="model-badge">MVP</span>
              </div>

              {/* Dashboard cards */}
              <div className="dashboard-grid">
                <button
                  type="button"
                  className="dashboard-card"
                  onClick={() => switchScanner("message")}
                >
                  <span className="dashboard-icon">💬</span>

                  <h3>Message Scanner</h3>

                  <p>
                    Analyze suspicious texts, messages, and
                    potential scam attempts.
                  </p>

                  <span className="dashboard-link">
                    Open scanner →
                  </span>
                </button>

                <button
                  type="button"
                  className="dashboard-card"
                  onClick={() => switchScanner("url")}
                >
                  <span className="dashboard-icon">🔗</span>

                  <h3>URL Scanner</h3>

                  <p>
                    Analyze URLs for patterns associated with
                    phishing attacks.
                  </p>

                  <span className="dashboard-link">
                    Open scanner →
                  </span>
                </button>

                <div className="dashboard-card dashboard-info">
                  <span className="dashboard-icon">🛡️</span>

                  <h3>Safety Center</h3>

                  <p>
                    Never share passwords, OTPs, or banking
                    details with unverified websites or people.
                  </p>
                </div>
              </div>

              {/* Safety notice */}
              <div className="dashboard-notice">
                <strong>Important Security Notice</strong>

                <p>
                  ScamShield AI provides experimental machine-learning
                  predictions. A result is not proof that a message
                  or URL is safe or malicious. Verify suspicious
                  content independently before taking action.
                </p>
              </div>

              {/* Quick actions */}
              <div className="recommendation-section">
                <h4>🛡️ Essential Safety Tips</h4>

                <ul>
                  <li>
                    Never share an OTP or password with someone
                    who contacts you unexpectedly.
                  </li>

                  <li>
                    Check the complete domain before opening
                    an unfamiliar link.
                  </li>

                  <li>
                    Verify payment requests through a separate,
                    trusted communication channel.
                  </li>

                  <li>
                    Do not assume a website is safe simply
                    because it uses HTTPS.
                  </li>
                </ul>
              </div>
            </div>
          </section>
          <section className="scanner-card history-section">
  <div className="url-scanner-title">
    <div>
      <h2>Recent Scan History</h2>
      <p>Your 10 most recent message and URL scans.</p>
    </div>

    <button
      className="clear-button"
      onClick={() => {
        localStorage.removeItem("scamshield-history");
        setScanHistory([]);
      }}
    >
      Clear History
    </button>
  </div>

  {scanHistory.length === 0 ? (
    <p>No scans yet. Scan a message or URL to see your history here.</p>
  ) : (
    <div className="history-list">
      {scanHistory.map((item) => (
        <div className="history-item" key={item.id}>
          <div>
            <strong>{item.type} Scan</strong>
            <p>{item.input}</p>
            <small>{item.time}</small>
          </div>

          <span className="risk-badge">{item.result}</span>
        </div>
      ))}
    </div>
  )}
    </section>
    </>
        )}

        {/* ================================== */}
        {/* URL SCANNER                        */}
        {/* ================================== */}

        {activeScanner === "url" && <URLScanner />}

        {/* ================================== */}
        {/* MESSAGE SCANNER                    */}
        {/* ================================== */}

        {activeScanner === "message" && (
          <section className="scanner-card">
            <div className="section-heading">
              <div>
                <h2>Message Scanner</h2>
                <p>Paste a suspicious message below.</p>
              </div>

              <span className="model-badge">Linear SVM</span>
            </div>

            <form onSubmit={handleScan}>
              <label htmlFor="message">
                Message content
              </label>

              <textarea
                id="message"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                placeholder="Example: Your account will be blocked. Click this link immediately..."
                maxLength={10000}
                rows={7}
              />

              <div className="input-footer">
                <span>
                  {message.length}/10000 characters
                </span>

                <button
                  type="button"
                  className="clear-button"
                  onClick={() => {
                    setMessage("");
                    setResult(null);
                    setError("");
                  }}
                >
                  Clear
                </button>
              </div>

              <button
                className="scan-button"
                type="submit"
                disabled={loading || !message.trim()}
              >
                {loading
                  ? "Analyzing message..."
                  : "🛡️ Scan Message"}
              </button>
            </form>

            {/* Error message */}
            {error && (
              <div className="error-box" role="alert">
                <strong>Scan unsuccessful</strong>
                <p>{error}</p>
              </div>
            )}

            {/* Scan result */}
            {result && (
              <section
                className={`result-card ${
                  result.is_scam
                    ? "result-danger"
                    : "result-safe"
                }`}
                aria-live="polite"
              >
                <div className="result-header">
                  <div>
                    <p className="result-label">
                      SCAN RESULT
                    </p>

                    <h3>
                      {result.is_scam
                        ? "Potential Scam Detected"
                        : "Not Classified as a Scam"}
                    </h3>
                  </div>

                  <span className="risk-badge">
                    {result.risk_level} Risk
                  </span>
                </div>

                <p>{result.explanation}</p>

                {result.risk_summary && (
                  <div className="recommendation-section">
                    <h4>🔎 Risk Analysis</h4>
                    <p>{result.risk_summary}</p>
                  </div>
                )}

                {result.red_flags?.length > 0 && (
                  <div className="recommendation-section">
                    <h4>🚩 Warning Signs</h4>

                    <ul>
                      {result.red_flags.map((flag, index) => (
                        <li key={index}>{flag}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.recommendations?.length > 0 && (
                  <div className="recommendation-section">
                    <h4>🛡️ Recommended Actions</h4>

                    <ul>
                      {result.recommendations.map(
                        (recommendation, index) => (
                          <li key={index}>
                            {recommendation}
                          </li>
                        )
                      )}
                    </ul>
                  </div>
                )}

                {result.safety_notice && (
                  <p className="safety-notice">
                    {result.safety_notice}
                  </p>
                )}

                <div className="result-details">
                  <div>
                    <span>Prediction</span>
                    <strong>{result.prediction}</strong>
                  </div>

                  <div>
                    <span>Model</span>
                    <strong>{result.model}</strong>
                  </div>
                </div>

                <p className="disclaimer">
                  This is an experimental ML prediction, not a
                  guarantee. Verify suspicious claims independently
                  and avoid sharipotenng passwords, OTPs, or banking details.
                </p>
              </section>
            )}
          </section>
        )}

        {/* Footer */}
        <footer className="footer">
          ScamShield AI · AI-assisted scam awareness
        </footer>
      </main>
    </div>
  );
}

export default App;