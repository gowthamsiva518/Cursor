"""
Symitar Core API response checker (Integration Manager playbook).

- Builds URL: {SYM_WSDL_DIRECTORY}/SymXchange/{SYM_VERSION}/{API_ENDPOINT}
- Builds SOAP envelope with DeviceInformation + AdministrativeCredentials
- POST with Content-Type: application/xml
- Classifies body text into ok / expected-empty / fault / network (playbook table)

Load credentials from .env (same keys as IM ConfigMap) or merge from kubectl ConfigMap.

Usage:
  python symitar_api_agent.py validate-env
  python symitar_api_agent.py fetch-config --namespace icu-aicc-prod-im
  python symitar_api_agent.py curl --api-endpoint AccountService.svc \\
      --fin-dto account --operation getAccount --request-file request_fragment.xml
  python symitar_api_agent.py run --api-endpoint ... --fin-dto account --operation getAccount \\
      --request-file request_fragment.xml
  python symitar_api_agent.py run-batch --checks symitar_api_checks.example.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Load .env from project root when present
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
except ImportError:
    pass

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore


CONFIGMAP_KEYS = (
    "SYM_WSDL_DIRECTORY",
    "SYM_VERSION",
    "SYM_CORE_API_DEVICE_TYPE",
    "SYM_CORE_API_DEVICE_NUMBER",
    "SYM_CORE_API_PASSWORD",
)

# Optional env keys merged with os.environ for requests / validation
SYM_EXTRA_ENV_KEYS = (
    "SYM_VERIFY_SSL",
    "SYM_HTTP_TIMEOUT_SEC",
    "SYM_MESSAGE_ID",
)


def resolved_symitar_env(overrides: dict[str, Any] | None) -> dict[str, str]:
    """
    Build env-like map: start from ``os.environ`` for SYM_* keys, then apply ``overrides``.

    An override value that is ``None`` or blank after ``strip()`` is **ignored** for every key
    (including password). That way the UI can send the full ``config`` object on every request
    without empty fields wiping values that only exist in ``.env`` / Settings.
    """
    keys = set(CONFIGMAP_KEYS) | set(SYM_EXTRA_ENV_KEYS)
    merged: dict[str, str] = {k: (os.environ.get(k) or "").strip() for k in keys}
    if not overrides:
        return merged
    for k, v in overrides.items():
        ku = str(k).strip()
        if ku not in keys:
            continue
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        merged[ku] = s
    return merged


@dataclass
class SymitarSettings:
    wsdl_directory: str
    version: str
    device_type: str
    device_number: str
    password: str
    verify_ssl: bool = False
    timeout_sec: float = 60.0
    message_id: str = "123456"

    @classmethod
    def from_environ(cls, env: dict[str, str] | None = None) -> SymitarSettings | None:
        e = env if env is not None else os.environ
        vals = {k: (e.get(k) or "").strip() for k in CONFIGMAP_KEYS}
        if not all(vals.values()):
            return None
        wsdl = vals["SYM_WSDL_DIRECTORY"].rstrip("/")
        verify = (e.get("SYM_VERIFY_SSL") or "").strip().lower() in ("1", "true", "yes")
        timeout = float((e.get("SYM_HTTP_TIMEOUT_SEC") or "60").strip() or "60")
        msg = (e.get("SYM_MESSAGE_ID") or "123456").strip() or "123456"
        return cls(
            wsdl_directory=wsdl,
            version=vals["SYM_VERSION"],
            device_type=vals["SYM_CORE_API_DEVICE_TYPE"],
            device_number=vals["SYM_CORE_API_DEVICE_NUMBER"],
            password=vals["SYM_CORE_API_PASSWORD"],
            verify_ssl=verify,
            timeout_sec=timeout,
            message_id=msg,
        )


def _find_kubectl() -> str | None:
    import shutil

    path = shutil.which("kubectl")
    if path:
        return path
    for candidate in (r"C:\kubectl\kubectl.exe", "/usr/local/bin/kubectl", "/usr/bin/kubectl"):
        if os.path.isfile(candidate):
            return candidate
    return None


def _run_kubectl_json(args: list[str], timeout: int = 60) -> dict[str, Any] | None:
    kubectl = _find_kubectl()
    if not kubectl:
        return None
    cmd = [kubectl] + args + ["-o", "json"]
    ctx = os.environ.get("KUBE_CONTEXT", "").strip()
    if ctx:
        cmd += ["--context", ctx]
    kcfg = os.environ.get("KUBE_CONFIG_PATH", "").strip()
    if kcfg:
        cmd += ["--kubeconfig", os.path.expanduser(kcfg)]
    import subprocess

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or f"kubectl exit {proc.returncode}"}
        return json.loads(proc.stdout)
    except Exception as ex:
        return {"error": str(ex)}


def parse_configmap_data(cm: dict[str, Any]) -> dict[str, str]:
    """Extract SYM_* keys from ConfigMap .data (flat keys or KEY=VALUE blobs)."""
    out: dict[str, str] = {}
    raw = cm.get("data") or {}
    if not isinstance(raw, dict):
        return out
    for key, val in raw.items():
        if not isinstance(val, str):
            continue
        if key in CONFIGMAP_KEYS:
            out[key] = val.strip()
            continue
        for line in val.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in CONFIGMAP_KEYS and v:
                    out[k] = v
    return out


def fetch_integration_manager_env(namespace: str, name: str | None = None) -> dict[str, str]:
    """
    Read integration-manager-env-{namespace} in namespace (Lens / kubectl).
    """
    cm_name = name or f"integration-manager-env-{namespace}"
    data = _run_kubectl_json(["get", "configmap", cm_name, "-n", namespace])
    if data is None:
        raise RuntimeError("kubectl not found; install kubectl or set PATH")
    if "error" in data and "data" not in data:
        raise RuntimeError(data["error"])
    return parse_configmap_data(data)


def symitar_url(settings: SymitarSettings, api_endpoint: str) -> str:
    # Do not use urllib.urljoin — it replaces the last path segment of the base URL.
    base = settings.wsdl_directory.rstrip("/")
    path = f"SymXchange/{settings.version}/{api_endpoint.lstrip('/')}"
    return f"{base}/{path}"


def build_soap_envelope(
    settings: SymitarSettings,
    fin_dto_namespace: str,
    api_operation_name: str,
    request_inner_xml: str,
) -> str:
    """
    fin_dto_namespace: last segment of xmlns:fin, e.g. 'account' for
    http://www.symxchange.generated.symitar.com/account/dto/account
    """
    fin_ns = f"http://www.symxchange.generated.symitar.com/{fin_dto_namespace}/dto/{fin_dto_namespace}"
    common_ns = "http://www.symxchange.generated.symitar.com/common/dto/common"
    inner = request_inner_xml.strip()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:fin="{fin_ns}"
    xmlns:common="{common_ns}">
    <soapenv:Header/>
    <soapenv:Body>
        <fin:{api_operation_name}>
            <Request common:MessageId="{_xml_escape_attr(settings.message_id)}">
                {inner}
                <DeviceInformation DeviceType="{_xml_escape_attr(settings.device_type)}" DeviceNumber="{_xml_escape_attr(settings.device_number)}"/>
                <Credentials>
                    <AdministrativeCredentials>
                        <Password>{_xml_escape_text(settings.password)}</Password>
                    </AdministrativeCredentials>
                </Credentials>
            </Request>
        </fin:{api_operation_name}>
    </soapenv:Body>
</soapenv:Envelope>"""


def _xml_escape_attr(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _xml_escape_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_curl_command(url: str, body: str, verify_ssl: bool) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="symitar-body-")
    os.close(fd)
    Path(path).write_text(body, encoding="utf-8")
    k = "" if verify_ssl else " -k"
    # Use --data-binary @file to preserve XML newlines
    return (
        f"curl{k} --location '{url}' \\\n"
        f"  --header 'Content-Type: application/xml' \\\n"
        f"  --data-binary @{path}\n"
        f"# temp body file: {path} (delete when done)"
    )


@dataclass
class TriageResult:
    category: str
    meaning: str
    action: str
    http_status: int | None = None
    detail: str = ""


def triage_response(status_code: int | None, body: str, error: str | None = None) -> TriageResult:
    """
    Map playbook failure table + success criteria.
    """
    text = (body or "").lower()
    err_l = (error or "").lower()

    if error and not body:
        if "timed out" in err_l or "timeout" in err_l:
            return TriageResult(
                "network",
                "Timeout connecting to SymXchange",
                "Verify namespace, cluster health, network path, and SYM_WSDL_DIRECTORY reachability.",
                status_code,
                error,
            )
        if "could not connect" in err_l or "connection refused" in err_l or "connection error" in err_l:
            return TriageResult(
                "network",
                "Could not connect",
                "Network issue — verify IM namespace, cluster health, and URL.",
                status_code,
                error,
            )

    combined = text + " " + err_l

    if "poster is off host" in combined:
        return TriageResult(
            "core",
            "Poster is off host",
            "Core-side issue — escalate to client / core admin.",
            status_code,
        )
    if "no service was found" in combined or "noservice" in combined.replace(" ", ""):
        return TriageResult(
            "syntax_version",
            "No service was found",
            "Syntax or SymXchange version mismatch — double-check ConfigMap SYM_VERSION and API endpoint.",
            status_code,
        )
    if "unauthorized" in combined or "not authorized" in combined:
        return TriageResult(
            "credentials",
            "Unauthorized",
            "Invalid credentials — check SYM_CORE_API_PASSWORD and SYM_CORE_API_DEVICE_TYPE / DEVICE_NUMBER.",
            status_code,
        )

    if "<soapenv:fault" in text or "<soap:fault" in text or "<fault" in text and "faultstring" in text:
        return TriageResult(
            "soap_fault",
            "SOAP Fault in response",
            "Inspect faultstring/faultcode; compare with Postman collection and request XML.",
            status_code,
        )

    if "the requested record was not found" in text:
        return TriageResult(
            "ok_expected",
            "Record not found (often valid for connectivity checks)",
            "Treat as valid connectivity for many read APIs; adjust request if you expected data.",
            status_code,
        )

    if status_code == 401:
        return TriageResult(
            "credentials",
            "HTTP 401 Unauthorized",
            "Check SYM_CORE_API_PASSWORD and device fields; confirm IM pod can reach core.",
            status_code,
        )

    if status_code == 200 and "<soapenv:envelope" in text and "fault" not in text[:500]:
        return TriageResult(
            "ok",
            "SOAP success envelope",
            "Log as verified for this API if business payload matches expectations.",
            status_code,
        )

    if status_code == 200:
        return TriageResult(
            "unknown",
            "HTTP 200 but unrecognized body",
            "Review raw response; extend triage patterns if needed.",
            status_code,
        )

    return TriageResult(
        "http_error",
        f"HTTP {status_code}",
        "Check URL, TLS (SYM_VERIFY_SSL), and server availability.",
        status_code,
    )


def run_symitar_request(
    settings: SymitarSettings,
    api_endpoint: str,
    fin_dto_namespace: str,
    api_operation_name: str,
    request_inner_xml: str,
) -> dict[str, Any]:
    if requests is None:
        raise RuntimeError("requests is required. pip install requests")

    url = symitar_url(settings, api_endpoint)
    body = build_soap_envelope(settings, fin_dto_namespace, api_operation_name, request_inner_xml)
    try:
        r = requests.post(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/xml; charset=utf-8"},
            timeout=settings.timeout_sec,
            verify=settings.verify_ssl,
        )
        triage = triage_response(r.status_code, r.text)
        return {
            "ok": triage.category in ("ok", "ok_expected"),
            "url": url,
            "http_status": r.status_code,
            "triage": asdict(triage),
            "response_preview": r.text[:4000] if r.text else "",
        }
    except requests.exceptions.Timeout as e:
        triage = triage_response(None, "", str(e))
        return {"ok": False, "url": url, "http_status": None, "triage": asdict(triage), "error": str(e)}
    except requests.exceptions.RequestException as e:
        triage = triage_response(None, "", str(e))
        return {"ok": False, "url": url, "http_status": None, "triage": asdict(triage), "error": str(e)}


def _print_triage_report(result: dict[str, Any]) -> None:
    t = result.get("triage")
    if not t:
        print(json.dumps(result, indent=2))
        return
    print("url:", result.get("url"))
    print("http_status:", result.get("http_status"))
    print("category:", t.get("category") if isinstance(t, dict) else t.category)
    print("meaning:", t.get("meaning") if isinstance(t, dict) else t.meaning)
    print("action:", t.get("action") if isinstance(t, dict) else t.action)
    detail = t.get("detail") if isinstance(t, dict) else t.detail
    if detail:
        print("detail:", detail)
    if result.get("error"):
        print("error:", result["error"])
    prev = result.get("response_preview")
    if prev:
        print("response_preview:\n", prev[:2000])


def cmd_validate_env(_: argparse.Namespace) -> int:
    s = SymitarSettings.from_environ()
    if not s:
        missing = [k for k in CONFIGMAP_KEYS if not (os.environ.get(k) or "").strip()]
        print("Missing or empty:", ", ".join(missing))
        print("Set these in .env (same names as IM ConfigMap) or run fetch-config and export.")
        return 1
    print("SYM_* environment is complete.")
    print("SYM_WSDL_DIRECTORY:", s.wsdl_directory[:80] + ("..." if len(s.wsdl_directory) > 80 else ""))
    print("SYM_VERSION:", s.version)
    print("Device type/number:", s.device_type, s.device_number)
    print("SYM_VERIFY_SSL:", s.verify_ssl, "timeout_sec:", s.timeout_sec)
    return 0


def cmd_fetch_config(args: argparse.Namespace) -> int:
    try:
        data = fetch_integration_manager_env(args.namespace, args.configmap_name)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1
    lines = [f"export {k}={_shell_quote(v)}" for k, v in sorted(data.items()) if k in CONFIGMAP_KEYS]
    if args.format == "env":
        print("\n".join(lines))
    else:
        print(json.dumps(data, indent=2))
    missing = [k for k in CONFIGMAP_KEYS if k not in data or not data[k]]
    if missing:
        print("# warning: missing keys after parse:", ", ".join(missing), file=sys.stderr)
        return 2
    return 0


def _shell_quote(s: str) -> str:
    if re.match(r"^[a-zA-Z0-9._/@:-]+$", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def cmd_curl(args: argparse.Namespace) -> int:
    s = SymitarSettings.from_environ()
    if not s:
        print("Incomplete SYM_* env. Run validate-env.", file=sys.stderr)
        return 1
    inner = _read_request_fragment(args)
    url = symitar_url(s, args.api_endpoint)
    body = build_soap_envelope(s, args.fin_dto, args.operation, inner)
    print(build_curl_command(url, body, s.verify_ssl))
    return 0


def _read_request_fragment(args: argparse.Namespace) -> str:
    if args.request_file:
        return Path(args.request_file).read_text(encoding="utf-8")
    if args.request_inline:
        return args.request_inline
    return "<!-- add request-specific XML via --request-file or --request-inline -->"


def cmd_run(args: argparse.Namespace) -> int:
    s = SymitarSettings.from_environ()
    if not s:
        print("Incomplete SYM_* env.", file=sys.stderr)
        return 1
    inner = _read_request_fragment(args)
    result = run_symitar_request(s, args.api_endpoint, args.fin_dto, args.operation, inner)
    _print_triage_report(result)
    return 0 if result.get("ok") else 1


def cmd_run_batch(args: argparse.Namespace) -> int:
    if yaml is None:
        print("PyYAML required for run-batch. pip install PyYAML", file=sys.stderr)
        return 1
    path = Path(args.checks)
    if not path.is_file():
        print(f"Not found: {path}", file=sys.stderr)
        return 1
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    checks = doc.get("checks") or []
    if not checks:
        print("No 'checks' list in YAML", file=sys.stderr)
        return 1

    env_override = dict(os.environ)
    cm_ns = doc.get("configmap_namespace")
    if cm_ns:
        try:
            merged = fetch_integration_manager_env(str(cm_ns), doc.get("configmap_name"))
            for k, v in merged.items():
                env_override[k] = v
        except RuntimeError as e:
            print("configmap fetch failed:", e, file=sys.stderr)
            return 1

    settings = SymitarSettings.from_environ(env_override)
    if not settings:
        print("Incomplete SYM_* after merge.", file=sys.stderr)
        return 1

    exit_code = 0
    for i, chk in enumerate(checks):
        name = chk.get("name") or f"check_{i}"
        api_endpoint = chk.get("api_endpoint") or chk.get("endpoint")
        fin_dto = chk.get("fin_dto") or chk.get("dto")
        operation = chk.get("operation") or chk.get("api_name")
        inner = chk.get("request_xml") or ""
        if not all([api_endpoint, fin_dto, operation]):
            print(f"[{name}] skip: need api_endpoint, fin_dto, operation", file=sys.stderr)
            exit_code = 1
            continue
        print(f"\n=== {name} ===")
        result = run_symitar_request(settings, api_endpoint, fin_dto, operation, inner)
        _print_triage_report(result)
        if not result.get("ok"):
            exit_code = 1
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Symitar Core API response checker (IM playbook)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate-env", help="Check SYM_* variables in environment")
    p_val.set_defaults(func=cmd_validate_env)

    p_fc = sub.add_parser("fetch-config", help="Print SYM_* from kubectl ConfigMap (Lens workflow)")
    p_fc.add_argument("--namespace", required=True, help="e.g. icu-aicc-prod-im")
    p_fc.add_argument("--configmap-name", default=None, help="default: integration-manager-env-{namespace}")
    p_fc.add_argument("--format", choices=("env", "json"), default="env")
    p_fc.set_defaults(func=cmd_fetch_config)

    def add_request_args(p: argparse.ArgumentParser) -> None:
        g = p.add_mutually_exclusive_group()
        g.add_argument("--request-file", help="XML fragment inside <Request> (device/credentials added by agent)")
        g.add_argument("--request-inline", help="Same as file but inline (careful with shell quoting)")

    p_curl = sub.add_parser("curl", help="Print a curl command (playbook template)")
    p_curl.add_argument("--api-endpoint", required=True, help="e.g. AccountService.svc")
    p_curl.add_argument("--fin-dto", required=True, help="XML namespace segment, e.g. account")
    p_curl.add_argument("--operation", required=True, help="SOAP operation element name, e.g. getAccount")
    add_request_args(p_curl)
    p_curl.set_defaults(func=cmd_curl)

    p_run = sub.add_parser("run", help="POST request and print triage")
    p_run.add_argument("--api-endpoint", required=True)
    p_run.add_argument("--fin-dto", required=True)
    p_run.add_argument("--operation", required=True)
    add_request_args(p_run)
    p_run.set_defaults(func=cmd_run)

    p_rb = sub.add_parser("run-batch", help="Run checks from YAML (optional ConfigMap merge)")
    p_rb.add_argument("--checks", default="symitar_api_checks.example.yaml")
    p_rb.set_defaults(func=cmd_run_batch)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
