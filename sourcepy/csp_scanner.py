import requests
import time
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 3


def get_csp(url):
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        time.sleep(RATE_LIMIT_DELAY)
        csp_header = response.headers.get('Content-Security-Policy')

        if csp_header:
            return csp_header
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"请求错误: {e}")
        return None


def analyze_csp(csp_header):
    policies = csp_header.split(';')
    analyzed_policies = []

    for policy in policies:
        policy_parts = policy.strip().split()
        directive = policy_parts[0].strip()
        sources = [source.strip() for source in policy_parts[1:]]

        analyzed_policies.append((directive, sources))

    return analyzed_policies


def generate_pdf_report(analyzed_csp, filename):
    data = [["指令", "来源"]] + analyzed_csp

    table = Table(data, colWidths=[200, 350])
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

    csp_header = get_csp(target_url)

    if csp_header:
        print(f"{target_url} 的内容安全策略（CSP）:")
        print(csp_header)

        analyzed_csp = analyze_csp(csp_header)
        for directive, sources in analyzed_csp:
            print(f"{directive}: {', '.join(sources)}")

        pdf_filename = f"{target_url}-csp_report.pdf"
        generate_pdf_report(analyzed_csp, pdf_filename)
        print(f"报告已生成: {pdf_filename}")

    else:
        print(f"{target_url} 未找到内容安全策略（CSP）")
