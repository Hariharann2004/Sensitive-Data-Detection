# pdf_utils.py
from PyPDF2 import PdfReader

def extract_text_from_pdf(path: str) -> str:
    text = []
    try:
        reader = PdfReader(path)
        for page in reader.pages:
            text.append(page.extract_text() or "")
    except Exception as e:
        text.append(f"[PDF read error: {e}]")
    return "\n".join(text)
