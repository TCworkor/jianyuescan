import requests
from bs4 import BeautifulSoup
import time
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 3

CSRF_TOKEN_NAMES = [
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "_csrf_token",
    "_csrf"
]

def find_forms(url):
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        time.sleep(RATE_LIMIT_DELAY)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"请求错误: {e}")
        return []


def check_csrf_token(form):
    for token_name in CSRF_TOKEN_NAMES:
        if form.find("input", {"name": token_name}):
            return True
    return False


def analyze_forms(forms):
    vulnerable_forms = []

    for form in forms:
        if not check_csrf_token(form):
            vulnerable_forms.append(form)

    return vulnerable_forms


def generate_pdf_report(url, vulnerable_forms, filename):
    data = [["表单的操作", "方法"]]
    for form in vulnerable_forms:
        data.append([form.get("action"), form.get("method")])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    doc = SimpleDocTemplate(filename, pagesize=letter)
    doc.build([table])


if __name__ == "__main__":
    target_url = input('请输入目标网站的URL: ')

    forms = find_forms(target_url)

    if forms:
        vulnerable_forms = analyze_forms(forms)

        if vulnerable_forms:
            print(f"在{target_url}发现易受攻击的表单:")
            for form in vulnerable_forms:
                print(f"表单操作: {form.get('action')} | 方法: {form.get('method')}")

            pdf_filename = f"{target_url}-csrf_vulnerable_forms_report.pdf"
            generate_pdf_report(target_url, vulnerable_forms, pdf_filename)
            print(f"报告已生成: {pdf_filename}")

        else:
            print(f"在{target_url}未发现CSRF漏洞")

    else:
        print(f"在{target_url}未找到表单")
