import secrets
import uuid

from flask import Flask, redirect, render_template, request, url_for

from app.service import audit_config_diff, audit_config_text

app = Flask(__name__, template_folder="app/templates")
app.config["SECRET_KEY"] = secrets.token_hex(16)

_RESULT_CACHE: dict[str, dict] = {}

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: _SEVERITY_RANK.get(item.get("severity"), 99))


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
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


def _store_result(payload: dict) -> str:
    token = uuid.uuid4().hex
    _RESULT_CACHE[token] = payload
    return token


def _pop_result(token: str | None) -> dict | None:
    if not token:
        return None
    return _RESULT_CACHE.pop(token, None)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        token = request.args.get("r")
        payload = _pop_result(token)
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
                payload["has_input"] = True
                old_text = _decode_file(old_file)
                new_text = _decode_file(new_file)
                diff_result = audit_config_diff(old_text, new_text)
                if diff_result and "new_findings" in diff_result:
                    diff_result["new_findings"] = _sort_findings(
                        diff_result["new_findings"]
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
                payload["has_input"] = True
                raw_config = _decode_file(uploaded_file)
                payload["report"] = _sort_findings(audit_config_text(raw_config))

    token = _store_result(payload)
    return redirect(url_for("index", r=token))


if __name__ == "__main__":
    app.run(debug=True)
