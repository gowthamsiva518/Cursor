"use client";

import { useState } from "react";

type ActionItem = {
  name: string;
  executed: boolean;
  outcome?: { message?: string };
  would_do?: string;
  error?: string;
};

type AgentResponse = {
  ok: boolean;
  error?: string;
  scenario_id?: string | null;
  conclusion?: string | null;
  next_action?: string | null;
  matched_rule?: boolean;
  actions?: ActionItem[];
};

function parseCodes(s: string): number[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
    .map((n) => parseInt(n, 10))
    .filter((n) => !isNaN(n));
}

export default function AgentPage() {
  const [codes, setCodes] = useState("500 503");
  const [callsOk, setCallsOk] = useState(false);
  const [callsFail, setCallsFail] = useState(false);
  const [restart, setRestart] = useState(false);
  const [authOk, setAuthOk] = useState(false);
  const [authFail, setAuthFail] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AgentResponse | null>(null);

  const run = async () => {
    const codeList = parseCodes(codes);
    if (codeList.length === 0) {
      setError("Enter at least one error code (e.g. 500 503 or 400).");
      return;
    }
    setError(null);
    setResult(null);
    setLoading(true);

    const context: Record<string, boolean> = {};
    if (callsOk) context.calls_ok = true;
    if (callsFail) context.calls_fail = true;
    if (restart) context.restart_detected = true;
    if (authOk) context.auth_ok = true;
    if (authFail) context.auth_fail = true;

    try {
      const res = await fetch("/api/agent/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error_codes: codeList, context, execute: false }),
      });
      const data: AgentResponse = await res.json();
      if (!res.ok) {
        setError(data.error || "Request failed");
        return;
      }
      if (!data.ok) {
        setError(data.error || "Agent error");
        return;
      }
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="wrap">
      <h1>Stream Server Alerts – Agent</h1>
      <p className="sub">
        Enter error codes and context, then run the agent to get conclusion, next action, and planned actions.
      </p>

      <div className={`card ${loading ? "loading" : ""}`}>
        <h2>Input</h2>
        <label htmlFor="codes">Error codes</label>
        <input
          id="codes"
          type="text"
          placeholder="e.g. 500 503 or 400"
          value={codes}
          onChange={(e) => setCodes(e.target.value)}
        />
        <p className="hint">Space- or comma-separated (e.g. 500, 503 or 400)</p>

        <label style={{ marginTop: "1rem" }}>Context (optional)</label>
        <div className="checks">
          <div className="check">
            <input type="checkbox" id="calls_ok" checked={callsOk} onChange={(e) => setCallsOk(e.target.checked)} />
            <label htmlFor="calls_ok">Calls OK</label>
          </div>
          <div className="check">
            <input type="checkbox" id="calls_fail" checked={callsFail} onChange={(e) => setCallsFail(e.target.checked)} />
            <label htmlFor="calls_fail">Calls fail</label>
          </div>
          <div className="check">
            <input type="checkbox" id="restart" checked={restart} onChange={(e) => setRestart(e.target.checked)} />
            <label htmlFor="restart">Restart detected</label>
          </div>
          <div className="check">
            <input type="checkbox" id="auth_ok" checked={authOk} onChange={(e) => setAuthOk(e.target.checked)} />
            <label htmlFor="auth_ok">Auth OK</label>
          </div>
          <div className="check">
            <input type="checkbox" id="auth_fail" checked={authFail} onChange={(e) => setAuthFail(e.target.checked)} />
            <label htmlFor="auth_fail">Auth fail</label>
          </div>
        </div>

        <button type="button" className="btn" onClick={run} disabled={loading}>
          Run agent
        </button>
        {error && <p className="err">{error}</p>}
      </div>

      {result && (
        <div className="card">
          <h2>Result</h2>
          <p className="scenario">
            {result.scenario_id ? `Scenario: ${result.scenario_id}` : result.error || "No scenario"}
          </p>
          <p className={`conclusion ${result.matched_rule && result.conclusion ? "" : "no-match"}`}>
            {result.matched_rule && result.conclusion
              ? result.conclusion
              : "No decision rule matched."}
          </p>
          {result.next_action && (
            <p className="next-action">
              <strong>Next action:</strong> {result.next_action}
            </p>
          )}
          {result.actions && result.actions.length > 0 && (
            <div className="agent-actions">
              <h3>Agent actions</h3>
              <ul>
                {result.actions.map((a, i) => (
                  <li key={i}>
                    <strong>{a.name}</strong> ({a.executed ? "Executed" : "Would do"}):{" "}
                    {a.outcome?.message ?? a.would_do ?? a.error ?? ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
