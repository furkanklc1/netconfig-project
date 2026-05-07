from flask import Flask, render_template, request

from app.service import audit_config_diff, audit_config_text

app = Flask(__name__, template_folder="app/templates")


@app.route("/", methods=["GET", "POST"])
def index():
    report = []
    diff_result = None
    has_input = False
    error = ""
    uploaded_name = ""
    old_uploaded_name = ""
    new_uploaded_name = ""
    analysis_mode = ""

    def _decode_file(uploaded_file) -> str:
        file_bytes = uploaded_file.read()
        try:
            return file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return file_bytes.decode("latin-1")

    if request.method == "POST":
        analysis_type = request.form.get("analysis_type", "single")
        if analysis_type == "diff":
            analysis_mode = "diff"
            old_file = request.files.get("old_config_file")
            new_file = request.files.get("new_config_file")
            if (
                old_file is None
                or not old_file.filename
                or new_file is None
                or not new_file.filename
            ):
                error = "Diff analizi için eski ve yeni dosyayı yükleyin."
            else:
                old_uploaded_name = old_file.filename
                new_uploaded_name = new_file.filename
                valid_ext = (".txt", ".cfg")
                if not old_uploaded_name.lower().endswith(valid_ext) or not new_uploaded_name.lower().endswith(valid_ext):
                    error = "Sadece .txt veya .cfg uzantılı dosyalar kabul edilir."
                else:
                    has_input = True
                    old_text = _decode_file(old_file)
                    new_text = _decode_file(new_file)
                    diff_result = audit_config_diff(old_text, new_text)
        else:
            analysis_mode = "single"
            uploaded_file = request.files.get("config_file")
            if uploaded_file is None or not uploaded_file.filename:
                error = "Lütfen bir .txt veya .cfg dosyası seçin."
            else:
                uploaded_name = uploaded_file.filename
                if not uploaded_name.lower().endswith((".txt", ".cfg")):
                    error = "Sadece .txt veya .cfg uzantılı dosyalar kabul edilir."
                else:
                    has_input = True
                    raw_config = _decode_file(uploaded_file)
                    report = audit_config_text(raw_config)
    return render_template(
        "index.html",
        report=report,
        diff_result=diff_result,
        has_input=has_input,
        error=error,
        uploaded_name=uploaded_name,
        old_uploaded_name=old_uploaded_name,
        new_uploaded_name=new_uploaded_name,
        analysis_mode=analysis_mode,
    )


if __name__ == "__main__":
    app.run(debug=True)
