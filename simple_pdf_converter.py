import os
import markdown
try:
    import pdfkit
    has_pdfkit = True
except ImportError:
    has_pdfkit = False

def convert_markdown_to_pdf():
    # Change to project directory
    os.chdir(r'C:\Hari\Hackathon\Nascomm\Project\ai-deidentification')

    # Read the markdown file
    with open('ux-details.md', 'r', encoding='utf-8') as f:
        markdown_content = f.read()

    # Convert markdown to HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables', 'codehilite'])

    # Enhanced CSS styling for better PDF output
    css_style = """
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px;
            font-size: 14px;
        }

        h1 {
            color: #2563eb;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 15px;
            font-size: 32px;
            margin-top: 40px;
            margin-bottom: 30px;
            text-align: center;
        }

        h2 {
            color: #1e40af;
            margin-top: 35px;
            margin-bottom: 20px;
            font-size: 24px;
            border-left: 4px solid #2563eb;
            padding-left: 15px;
        }

        h3 {
            color: #374151;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 20px;
        }

        h4 {
            color: #4b5563;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 16px;
            font-weight: 600;
        }

        h5 {
            color: #6b7280;
            margin-top: 15px;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }

        p {
            margin-bottom: 12px;
            text-align: justify;
        }

        ul, ol {
            padding-left: 25px;
            margin-bottom: 15px;
        }

        li {
            margin-bottom: 6px;
        }

        ul li {
            list-style-type: disc;
        }

        ul ul li {
            list-style-type: circle;
        }

        ul ul ul li {
            list-style-type: square;
        }

        code {
            background-color: #f3f4f6;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            color: #e11d48;
        }

        pre {
            background-color: #f9fafb;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #2563eb;
            font-size: 12px;
            overflow-x: auto;
        }

        strong {
            color: #1f2937;
            font-weight: 700;
        }

        em {
            font-style: italic;
            color: #4b5563;
        }

        blockquote {
            border-left: 4px solid #d1d5db;
            margin: 20px 0;
            padding: 10px 20px;
            background-color: #f9fafb;
            font-style: italic;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-size: 13px;
        }

        th, td {
            border: 1px solid #d1d5db;
            padding: 10px;
            text-align: left;
        }

        th {
            background-color: #f3f4f6;
            font-weight: 600;
            color: #374151;
        }

        tr:nth-child(even) {
            background-color: #f9fafb;
        }

        .toc {
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 20px;
            margin: 30px 0;
            border-radius: 8px;
        }

        .toc h2 {
            margin-top: 0;
            color: #2563eb;
        }

        .page-break {
            page-break-before: always;
        }

        .no-break {
            page-break-inside: avoid;
        }

        @media print {
            body {
                font-size: 12px;
                padding: 20px;
            }

            h1 {
                font-size: 28px;
            }

            h2 {
                font-size: 20px;
            }

            h3 {
                font-size: 18px;
            }

            .page-break {
                page-break-before: always;
            }
        }
    </style>
    """

    # Create complete HTML document
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AI De-identification System - Comprehensive UX Design Analysis</title>
        {css_style}
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    # Save HTML file first
    with open('ux-details.html', 'w', encoding='utf-8') as f:
        f.write(full_html)
    print("✅ HTML file created: ux-details.html")

    # Try to convert to PDF using pdfkit if available
    if has_pdfkit:
        options = {
            'page-size': 'A4',
            'margin-top': '1in',
            'margin-right': '1in',
            'margin-bottom': '1in',
            'margin-left': '1in',
            'encoding': 'UTF-8',
            'no-outline': None,
            'enable-local-file-access': None,
            'print-media-type': None,
        }

        try:
            pdfkit.from_file('ux-details.html', 'ux-details.pdf', options=options)
            print("✅ PDF created successfully: ux-details.pdf")

            # Get file sizes
            html_size = os.path.getsize('ux-details.html')
            pdf_size = os.path.getsize('ux-details.pdf')

            print(f"📄 HTML size: {html_size:,} bytes ({html_size/1024/1024:.2f} MB)")
            print(f"📄 PDF size: {pdf_size:,} bytes ({pdf_size/1024/1024:.2f} MB)")
            print(f"📍 PDF location: {os.path.abspath('ux-details.pdf')}")

            return True

        except Exception as e:
            print(f"❌ Error creating PDF with pdfkit: {e}")
            print("💡 You may need to install wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html")
            print("📝 HTML file is available for manual conversion or viewing in browser")
            return False
    else:
        print("📝 pdfkit not available. HTML file created for manual conversion.")
        print("💡 Install pdfkit with: pip install pdfkit")
        print("💡 And download wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html")
        return False

if __name__ == "__main__":
    convert_markdown_to_pdf()