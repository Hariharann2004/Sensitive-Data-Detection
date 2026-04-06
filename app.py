# app.py
from flask import Flask, render_template_string, request
from detector import detect_sensitive_data
from pdf_utils import extract_text_from_pdf
import os
import pandas as pd

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Sensitive Data Detection & Prevention</title>
<style>
    body{font-family:Segoe UI,Roboto,Arial,sans-serif;
         background:linear-gradient(135deg,#74ebd5 0%,#ACB6E5 100%);
         margin:0;padding:0}
    .container{max-width:920px;margin:48px auto;background:#fff;border-radius:16px;
               box-shadow:0 12px 24px rgba(0,0,0,.15);padding:28px}
    h1{margin:0 0 8px}
    p{color:#555;margin:0 0 16px}
    form{margin:18px 0}
    input[type=file]{padding:10px;border:1px solid #ddd;border-radius:8px}
    .btn{background:#3498db;color:#fff;border:none;padding:10px 18px;border-radius:8px;
         font-weight:600;cursor:pointer;margin-left:8px}
    .btn:hover{background:#2779b5}
    .card{margin-top:20px;background:#f7f9fb;border-radius:12px;padding:16px}
    .decision{font-weight:800;font-size:18px;margin-bottom:10px}
    .block{color:#e74c3c}.warn{color:#f39c12}.allow{color:#27ae60}
    table{width:100%;border-collapse:collapse;margin-top:8px}
    th{background:#34495e;color:#fff;padding:10px;text-align:left}
    td{padding:10px;border-bottom:1px solid #e5e7eb;background:#fff}
    tr:hover td{background:#eef6ff}
</style>
</head>
<body>
<div class="container">
  <h1>🔒 Sensitive Data Detection & Prevention</h1>
  <p>Upload a TXT / PDF / CSV file. We’ll scan for PAN, Aadhaar, card numbers (with Luhn), emails, phones, IPs, and sensitive keywords.</p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required />
    <button class="btn" type="submit">Upload & Analyze</button>
  </form>

  {% if results is not none %}
  <div class="card">
    <div class="decision {{ decision|lower }}">Final Decision: {{ decision }}</div>
    {% if results %}
      <table>
        <tr><th>Type</th><th>Value</th></tr>
        {% for r in results %}
        <tr><td>{{ r.type }}</td><td>{{ r.value }}</td></tr>
        {% endfor %}
      </table>
    {% else %}
      <p>No sensitive items found.</p>
    {% endif %}
  </div>
  {% endif %}
</div>
</body>
</html>
"""

@app.route("/", methods=["GET","POST"])
def index():
    results, decision = None, None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            os.makedirs("uploads", exist_ok=True)
            p = os.path.join("uploads", f.filename)
            f.save(p)

            text = ""
            name = f.filename.lower()
            if name.endswith(".pdf"):
                text = extract_text_from_pdf(p)
            elif name.endswith(".csv"):
                try:
                    df = pd.read_csv(p, dtype=str)
                    text = df.to_string(index=False)
                except Exception as e:
                    text = f"[CSV read error: {e}]"
            else:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()

            results, decision = detect_sensitive_data(text)
    return render_template_string(TEMPLATE, results=results, decision=decision)

if __name__ == "__main__":
    app.run(debug=True)
