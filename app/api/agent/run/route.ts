import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import path from "path";

const AGENT_API_URL = process.env.AGENT_API_URL;

export async function POST(request: NextRequest) {
  let body: { error_codes?: number[]; context?: Record<string, unknown>; execute?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body" }, { status: 400 });
  }

  const error_codes = body.error_codes;
  if (!Array.isArray(error_codes) || error_codes.length === 0) {
    return NextResponse.json({ ok: false, error: "error_codes required (e.g. [500, 503])" }, { status: 400 });
  }

  const payload = {
    error_codes: error_codes.map(Number).filter((n) => !isNaN(n)),
    context: body.context || {},
    execute: body.execute === true,
  };

  if (AGENT_API_URL) {
    try {
      const res = await fetch(`${AGENT_API_URL.replace(/\/$/, "")}/api/agent/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      return NextResponse.json(data);
    } catch (e) {
      return NextResponse.json(
        { ok: false, error: e instanceof Error ? e.message : "Proxy to agent failed" },
        { status: 502 }
      );
    }
  }

  // Run Python agent via stdin/stdout
  const scriptPath = path.join(process.cwd(), "agent_stdin.py");
  return new Promise<NextResponse>((resolve) => {
    const proc = spawn("python3", [scriptPath], {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    proc.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
    proc.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));

    proc.on("error", (err) => {
      resolve(
        NextResponse.json(
          { ok: false, error: `Failed to run Python agent: ${err.message}. Install deps: pip install -r requirements.txt` },
          { status: 500 }
        )
      );
    });

    proc.on("close", (code) => {
      try {
        const data = JSON.parse(stdout || "{}");
        if (data.ok === false && !data.error) data.error = stderr || "Agent script failed";
        resolve(NextResponse.json(data));
      } catch {
        resolve(
          NextResponse.json(
            { ok: false, error: stderr || stdout || `Process exited with code ${code}` },
            { status: 500 }
          )
        );
      }
    });

    proc.stdin.write(JSON.stringify(payload), () => proc.stdin.end());
  });
}
