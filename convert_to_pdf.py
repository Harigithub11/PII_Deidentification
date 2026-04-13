import os
import markdown
from weasyprint import HTML, CSS

def convert_markdown_to_pdf():
    # Change to project directory
    os.chdir(r'C:\Hari\Hackathon\Nascomm\Project\ai-deidentification')

    # Read the markdown file
    with open('ux-details.md', 'r', encoding='utf-8') as f:
        markdown_content = f.read()

    # Convert markdown to HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables', 'codehilite'])

    # Add CSS styling for better PDF output
    css_style = """
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        line-height: 1.6;
        color: #333;
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
        font-size: 11pt;
    }

    h1 {
        color: #2563eb;
        border-bottom: 2px solid #2563eb;
        padding-bottom: 10px;
        font-size: 24pt;
        margin-top: 30px;
        margin-bottom: 20px;
        page-break-after: avoid;
    }

    h2 {
        color: #1e40af;
        margin-top: 25px;
        margin-bottom: 15px;
        font-size: 18pt;
        page-break-after: avoid;
    }

    h3 {
        color: #374151;
        margin-top: 20px;
        margin-bottom: 10px;
        font-size: 14pt;
        page-break-after: avoid;
    }

    h4 {
        color: #4b5563;
        margin-top: 15px;
        margin-bottom: 8px;
        font-size: 12pt;
        page-break-after: avoid;
    }

    p {
        margin-bottom: 8px;
        text-align: justify;
    }

    ul, ol {
        padding-left: 20px;
        margin-bottom: 10px;
    }

    li {
        margin-bottom: 4px;
    }

    code {
        background-color: #f3f4f6;
        padding: 2px 4px;
        border-radius: 3px;
        font-family: 'Courier New', monospace;
        font-size: 10pt;
    }

    pre {
        background-color: #f9fafb;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #2563eb;
        font-size: 10pt;
        page-break-inside: avoid;
    }

    strong {
        color: #1f2937;
    }

    em {
        font-style: italic;
    }

    .page-break {
        page-break-before: always;
    }

    @page {
        margin: 2cm;
        size: A4;

        @top-center {
            content: "AI De-identification System - UX Design Analysis";
            font-size: 10pt;
            color: #6b7280;
        }

        @bottom-center {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 10pt;
            color: #6b7280;
        }
    }
    """

    # Create complete HTML document
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AI De-identification System - UX Details</title>
        <style>{css_style}</style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    # Convert to PDF
    try:
        html_doc = HTML(string=full_html)
        html_doc.write_pdf('ux-details.pdf')
        print("✅ PDF created successfully: ux-details.pdf")
        print(f"📄 File location: {os.path.abspath('ux-details.pdf')}")

        # Get file size
        size = os.path.getsize('ux-details.pdf')
        print(f"📏 File size: {size:,} bytes ({size/1024/1024:.2f} MB)")

    except Exception as e:
        print(f"❌ Error creating PDF: {e}")
        print("Note: Make sure WeasyPrint is installed: pip install weasyprint")
        return False

    return True

if __name__ == "__main__":
    convert_markdown_to_pdf()