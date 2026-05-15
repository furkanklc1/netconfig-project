import io
import secrets
import sys
import uuid
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

# Çalışma dizini IDE/terminalden farklı olsa bile `app.*` importları çalışsın.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from app.service import (
    audit_bundle,
    audit_config_diff,
    count_categories,
    validate_config_text,
)

app = Flask(__name__, template_folder="app/templates")
app.config["SECRET_KEY"] = secrets.token_hex(16)

_VIEW_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_DOWNLOAD_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_MAX = 64

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: _SEVERITY_RANK.get(item.get("severity"), 99))


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _decode_file(uploaded_file) -> str:
    file_bytes = uploaded_file.read()
    try:
        return file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return file_bytes.decode("latin-1")


def _store_result(payload: dict) -> tuple[str, str]:
    view_token = uuid.uuid4().hex
    download_token = uuid.uuid4().hex
    _VIEW_CACHE[view_token] = payload
    _DOWNLOAD_CACHE[download_token] = payload
    while len(_VIEW_CACHE) > _CACHE_MAX:
        _VIEW_CACHE.popitem(last=False)
    while len(_DOWNLOAD_CACHE) > _CACHE_MAX:
        _DOWNLOAD_CACHE.popitem(last=False)
    return view_token, download_token


def _pop_view(token: str | None) -> dict | None:
    if not token:
        return None
    return _VIEW_CACHE.pop(token, None)


def _peek_download(token: str | None) -> dict | None:
    if not token:
        return None
    return _DOWNLOAD_CACHE.get(token)


def _render_report_html(payload: dict) -> str:
    report = payload.get("report", [])
    return render_template(
        "report.html",
        report=report,
        severity_counts=_count_severities(report),
        category_counts=count_categories(report),
        device_info=payload.get("device_info"),
        uploaded_name=payload.get("uploaded_name", ""),
        generated_at=datetime.now().strftime("%d.%m.%Y %H:%M"),
    )


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        token = request.args.get("r")
        download_token = request.args.get("dl", "")
        payload = _pop_view(token)
        if payload is None:
            payload = {}
        report = payload.get("report", [])
        diff_result = payload.get("diff_result")
        return render_template(
            "index.html",
            report=report,
            severity_counts=_count_severities(report),
            diff_result=diff_result,
            has_input=payload.get("has_input", False),
            error=payload.get("error", ""),
            uploaded_name=payload.get("uploaded_name", ""),
            old_uploaded_name=payload.get("old_uploaded_name", ""),
            new_uploaded_name=payload.get("new_uploaded_name", ""),
            analysis_mode=payload.get("analysis_mode", ""),
            device_info=payload.get("device_info"),
            download_token=download_token,
        )

    payload: dict = {
        "report": [],
        "diff_result": None,
        "has_input": False,
        "error": "",
        "uploaded_name": "",
        "old_uploaded_name": "",
        "new_uploaded_name": "",
        "analysis_mode": "",
        "device_info": None,
    }

    analysis_type = request.form.get("analysis_type", "single")

    if analysis_type == "diff":
        payload["analysis_mode"] = "diff"
        old_file = request.files.get("old_config_file")
        new_file = request.files.get("new_config_file")
        if (
            old_file is None
            or not old_file.filename
            or new_file is None
            or not new_file.filename
        ):
            payload["error"] = "Diff analizi için eski ve yeni dosyayı yükleyin."
        else:
            payload["old_uploaded_name"] = old_file.filename
            payload["new_uploaded_name"] = new_file.filename
            valid_ext = (".txt", ".cfg")
            if not payload["old_uploaded_name"].lower().endswith(valid_ext) or not payload[
                "new_uploaded_name"
            ].lower().endswith(valid_ext):
                payload["error"] = "Sadece .txt veya .cfg uzantılı dosyalar kabul edilir."
            else:
                old_text = _decode_file(old_file)
                new_text = _decode_file(new_file)
                old_valid, old_error = validate_config_text(old_text)
                new_valid, new_error = validate_config_text(new_text)
                if not old_valid:
                    payload["error"] = (
                        f"Eski dosya ('{payload['old_uploaded_name']}'): {old_error}"
                    )
                    payload["old_uploaded_name"] = ""
                    payload["new_uploaded_name"] = ""
                elif not new_valid:
                    payload["error"] = (
                        f"Yeni dosya ('{payload['new_uploaded_name']}'): {new_error}"
                    )
                    payload["old_uploaded_name"] = ""
                    payload["new_uploaded_name"] = ""
                else:
                    payload["has_input"] = True
                    diff_result = audit_config_diff(old_text, new_text)
                    if diff_result:
                        if "new_findings" in diff_result:
                            diff_result["new_findings"] = _sort_findings(
                                diff_result["new_findings"]
                            )
                        if "resolved_findings" in diff_result:
                            diff_result["resolved_findings"] = _sort_findings(
                                diff_result["resolved_findings"]
                            )
                    payload["diff_result"] = diff_result
    else:
        payload["analysis_mode"] = "single"
        uploaded_file = request.files.get("config_file")
        if uploaded_file is None or not uploaded_file.filename:
            payload["error"] = "Lütfen bir .txt veya .cfg dosyası seçin."
        else:
            payload["uploaded_name"] = uploaded_file.filename
            if not payload["uploaded_name"].lower().endswith((".txt", ".cfg")):
                payload["error"] = "Sadece .txt veya .cfg uzantılı dosyalar kabul edilir."
            else:
                raw_config = _decode_file(uploaded_file)
                is_valid, error_message = validate_config_text(raw_config)
                if not is_valid:
                    payload["error"] = error_message
                    payload["uploaded_name"] = ""
                else:
                    payload["has_input"] = True
                    report, device_info = audit_bundle(raw_config)
                    payload["report"] = _sort_findings(report)
                    payload["device_info"] = device_info

    view_token, download_token = _store_result(payload)
    return redirect(url_for("index", r=view_token, dl=download_token))


@app.route("/download/html/<token>")
def download_html(token: str):
    payload = _peek_download(token)
    if payload is None or not payload.get("report"):
        abort(404)
    html = _render_report_html(payload)
    filename = _safe_filename(payload.get("uploaded_name"), ".html")
    return Response(
        html,
        mimetype="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/download/pdf/<token>")
def download_pdf(token: str):
    payload = _peek_download(token)
    if payload is None or not payload.get("report"):
        abort(404)
    try:
        from xhtml2pdf import pisa
    except ImportError:
        return Response(
            "PDF üretimi için 'xhtml2pdf' paketi yüklü değil.\n"
            "Kurmak için: pip install xhtml2pdf",
            status=503,
            mimetype="text/plain; charset=utf-8",
        )

    html = _render_report_html(payload)
    buffer = io.BytesIO()
    result = pisa.CreatePDF(src=html, dest=buffer, encoding="utf-8")
    if result.err:
        return Response("PDF oluşturulurken hata.", status=500, mimetype="text/plain")
    filename = _safe_filename(payload.get("uploaded_name"), ".pdf")
    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _safe_filename(uploaded_name: str | None, extension: str) -> str:
    base = (uploaded_name or "audit").rsplit(".", 1)[0]
    base = "".join(c for c in base if c.isalnum() or c in ("-", "_")) or "audit"
    return f"netconfig-{base}{extension}"


if __name__ == "__main__":
    app.run(debug=True)
