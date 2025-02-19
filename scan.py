import argparse
import sys
import os

# 设置sourcepy目录路径（假设源代码存放在该目录下）
sourcepy_dir = os.path.join(os.getcwd(), "sourcepy")

# 将sourcepy目录添加到系统路径中，方便导入模块
sys.path.insert(0, sourcepy_dir)


# 定义不同的扫描模块
def run_csp_scan(args):
    from sourcepy.csp_scanner import get_csp, analyze_csp, generate_pdf_report  # 正确导入
    csp_header = get_csp(args.url)
    if csp_header:
        print(f"CSP 头信息: {csp_header}")
        analyzed_csp = analyze_csp(csp_header)
        for directive, sources in analyzed_csp:
            print(f"{directive}: {', '.join(sources)}")
        if args.report:
            generate_pdf_report(analyzed_csp, f"{args.url}-csp_report.pdf")
            print("PDF 报告已生成。")
    else:
        print("未找到 CSP 头信息。")


def run_csrf_scan(args):
    from sourcepy.csrf_scanner import find_forms, analyze_forms, generate_pdf_report  # 正确导入
    forms = find_forms(args.url)
    if forms:
        vulnerable_forms = analyze_forms(forms)
        if vulnerable_forms:
            print(f"在 {args.url} 发现易受攻击的表单：")
            for form in vulnerable_forms:
                print(f"操作: {form.get('action')} | 方法: {form.get('method')}")
            pdf_filename = f"{args.url}-csrf_vulnerable_forms_report.pdf"
            generate_pdf_report(args.url, vulnerable_forms, pdf_filename)
            print(f"报告已生成：{pdf_filename}")
        else:
            print(f"在 {args.url} 未发现 CSRF 漏洞。")
    else:
        print(f"在 {args.url} 未找到表单。")


def run_sql_scan(args):
    from sourcepy.sql_scanner import test_sql_injection, generate_pdf_report  # 正确导入
    params = args.sql_params.split(',')
    results = test_sql_injection(args.url, params, args.bin_id, args.api_key)
    for result in results:
        print(f"发现漏洞: {result[1]} - 参数: {result[0]} - 负载: {result[2]}")
    pdf_filename = f"{args.url}-sql_injection_report.pdf"
    generate_pdf_report(results, pdf_filename)
    print(f"报告已生成：{pdf_filename}")


def run_xss_scan(args):
    from sourcepy.xss_scanner import test_xss_vulnerabilities, generate_pdf_report  # 正确导入
    params = args.xss_params.split(',')
    results = test_xss_vulnerabilities(args.url, params)
    for result in results:
        print(f"发现 XSS 漏洞: {result[1]} - 参数: {result[0]} - 负载: {result[2]}")
    pdf_filename = f"{args.url}-xss_report.pdf"
    generate_pdf_report(results, pdf_filename)
    print(f"报告已生成：{pdf_filename}")


# 主函数：解析命令行参数并执行相应的扫描
def main():
    parser = argparse.ArgumentParser(description="Web 安全扫描工具", epilog="请使用 -m 指定扫描模块。")

    # 定义命令行参数
    parser.add_argument("-m", "--module", choices=["csp", "csrf", "sql", "xss"], required=True,
                        help="选择扫描模块：csp、csrf、sql 或 xss。")
    parser.add_argument("url", help="目标网站的 URL。")
    parser.add_argument("--report", action="store_true", help="生成 PDF 报告（仅适用于 CSP 扫描）。")

    # CSRF扫描特有的参数
    parser_csrf = parser.add_argument_group('CSRF 扫描选项')
    parser_csrf.add_argument("--csrf-token-name", help="指定 CSRF token 名称（默认自动检测）。")

    # SQL扫描特有的参数
    parser_sql = parser.add_argument_group('SQL 扫描选项')
    parser_sql.add_argument("--sql-params", required=True, help="逗号分隔的参数列表，用于 SQL 注入测试。")
    parser_sql.add_argument("--bin-id", required=True, help="RequestBin ID，用于基于通道的 SQL 注入。")
    parser_sql.add_argument("--api-key", required=True, help="RequestBin API 密钥。")

    # XSS扫描特有的参数
    parser_xss = parser.add_argument_group('XSS 扫描选项')
    parser_xss.add_argument("--xss-params", required=True, help="逗号分隔的参数列表，用于 XSS 测试。")

    # 解析命令行参数
    args = parser.parse_args()

    # 根据模块参数调用不同的扫描函数
    if args.module == "csp":
        run_csp_scan(args)
    elif args.module == "csrf":
        run_csrf_scan(args)
    elif args.module == "sql":
        run_sql_scan(args)
    elif args.module == "xss":
        run_xss_scan(args)


if __name__ == "__main__":
    main()
