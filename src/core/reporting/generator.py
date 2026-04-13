"""
Report Generator

Generates reports in multiple formats (PDF, Excel, JSON, CSV) using templates
and data from analytics engines.
"""

import io
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4
from enum import Enum
from dataclasses import dataclass

import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template

from ..config.settings import get_settings
from .engine import ReportRequest

logger = logging.getLogger(__name__)
settings = get_settings()


class ReportFormat(str, Enum):
    """Supported report output formats."""
    PDF = "pdf"
    EXCEL = "excel"
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class TemplateType(str, Enum):
    """Report template types."""
    AUDIT_TRAIL = "audit_trail"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CUSTOM = "custom"


@dataclass
class ReportTemplate:
    """Report template configuration."""
    name: str
    template_type: TemplateType
    template_file: str
    supported_formats: List[ReportFormat]
    variables: Dict[str, Any]
    styling: Dict[str, Any]


@dataclass
class GeneratedReport:
    """Information about a generated report file."""
    file_path: str
    file_size_bytes: int
    file_hash: str
    format: ReportFormat
    generation_time_ms: int
    metadata: Dict[str, Any]


class ReportGenerator:
    """Main report generation engine."""
    
    def __init__(self):
        self.output_dir = Path(settings.output_dir) / "reports"
        self.templates_dir = Path(__file__).parent / "templates"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Register custom filters
        self._register_custom_filters()
        
        # Load report templates
        self._load_templates()
    
    def _register_custom_filters(self):
        """Register custom Jinja2 filters for report generation."""
        
        @self.jinja_env.filter('format_datetime')
        def format_datetime(value, format_str='%Y-%m-%d %H:%M:%S'):
            """Format datetime with custom format."""
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except:
                    return value
            if isinstance(value, datetime):
                return value.strftime(format_str)
            return str(value)
        
        @self.jinja_env.filter('format_number')
        def format_number(value, decimal_places=2):
            """Format number with specified decimal places."""
            try:
                return f"{float(value):,.{decimal_places}f}"
            except (ValueError, TypeError):
                return str(value)
        
        @self.jinja_env.filter('format_percentage')
        def format_percentage(value, decimal_places=1):
            """Format percentage with % symbol."""
            try:
                return f"{float(value):.{decimal_places}f}%"
            except (ValueError, TypeError):
                return str(value)
        
        @self.jinja_env.filter('severity_color')
        def severity_color(severity):
            """Get color for severity level."""
            colors = {
                'low': '#28a745',
                'medium': '#ffc107', 
                'high': '#fd7e14',
                'critical': '#dc3545'
            }
            return colors.get(severity.lower(), '#6c757d')
        
        @self.jinja_env.filter('truncate_text')
        def truncate_text(text, length=50):
            """Truncate text to specified length."""
            if len(str(text)) > length:
                return str(text)[:length] + '...'
            return str(text)
    
    def _load_templates(self):
        """Load available report templates."""
        self.templates = {
            TemplateType.AUDIT_TRAIL: ReportTemplate(
                name="Audit Trail Report",
                template_type=TemplateType.AUDIT_TRAIL,
                template_file="audit_trail.html",
                supported_formats=[ReportFormat.PDF, ReportFormat.HTML, ReportFormat.EXCEL],
                variables={
                    "title": "Audit Trail Report",
                    "show_charts": True,
                    "show_details": True
                },
                styling={
                    "primary_color": "#0066cc",
                    "header_bg": "#f8f9fa",
                    "table_stripe": "#f8f9fa"
                }
            ),
            TemplateType.COMPLIANCE: ReportTemplate(
                name="Compliance Report",
                template_type=TemplateType.COMPLIANCE,
                template_file="compliance.html", 
                supported_formats=[ReportFormat.PDF, ReportFormat.HTML, ReportFormat.EXCEL],
                variables={
                    "title": "Compliance Report",
                    "show_compliance_matrix": True,
                    "show_violations": True
                },
                styling={
                    "primary_color": "#28a745",
                    "warning_color": "#ffc107",
                    "danger_color": "#dc3545"
                }
            ),
            TemplateType.SECURITY: ReportTemplate(
                name="Security Analysis Report",
                template_type=TemplateType.SECURITY,
                template_file="security.html",
                supported_formats=[ReportFormat.PDF, ReportFormat.HTML, ReportFormat.JSON],
                variables={
                    "title": "Security Analysis Report",
                    "show_threat_analysis": True,
                    "show_recommendations": True
                },
                styling={
                    "primary_color": "#dc3545",
                    "alert_bg": "#f8d7da"
                }
            )
        }
    
    async def generate_report_file(self, data: Dict[str, Any], request: ReportRequest,
                                 template_name: str) -> Dict[str, Any]:
        """
        Generate report file in specified format.
        
        Args:
            data: Report data from analytics engines
            request: Report generation request
            template_name: Name of template to use
            
        Returns:
            Information about generated report file
        """
        start_time = datetime.utcnow()
        
        try:
            # Determine output format
            output_format = ReportFormat(request.output_format.lower())
            
            # Get template
            template_type = self._get_template_type(template_name)
            template_config = self.templates.get(template_type)
            
            if not template_config:
                raise ValueError(f"Template not found: {template_name}")
            
            # Generate report based on format
            if output_format == ReportFormat.PDF:
                result = await self._generate_pdf_report(data, request, template_config)
            elif output_format == ReportFormat.EXCEL:
                result = await self._generate_excel_report(data, request, template_config)
            elif output_format == ReportFormat.JSON:
                result = await self._generate_json_report(data, request, template_config)
            elif output_format == ReportFormat.CSV:
                result = await self._generate_csv_report(data, request, template_config)
            elif output_format == ReportFormat.HTML:
                result = await self._generate_html_report(data, request, template_config)
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
            
            # Calculate generation time
            generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            result["generation_time_ms"] = int(generation_time)
            
            logger.info(f"Report generated: {result['file_path']} in {generation_time}ms")
            return result
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    def _get_template_type(self, template_name: str) -> TemplateType:
        """Determine template type from template name."""
        if "audit" in template_name.lower():
            return TemplateType.AUDIT_TRAIL
        elif "compliance" in template_name.lower():
            return TemplateType.COMPLIANCE
        elif "security" in template_name.lower():
            return TemplateType.SECURITY
        elif "performance" in template_name.lower():
            return TemplateType.PERFORMANCE
        else:
            return TemplateType.CUSTOM
    
    async def _generate_html_report(self, data: Dict[str, Any], request: ReportRequest,
                                  template_config: ReportTemplate) -> Dict[str, Any]:
        """Generate HTML report."""
        try:
            # Load template
            template = self.jinja_env.get_template(template_config.template_file)
            
            # Prepare template variables
            template_vars = {
                **template_config.variables,
                **template_config.styling,
                "report_data": data,
                "request": request,
                "generated_at": datetime.utcnow(),
                "generator_info": {
                    "system": "PII De-identification System",
                    "version": settings.app_version
                }
            }
            
            # Render HTML
            html_content = template.render(**template_vars)
            
            # Save to file
            filename = f"report_{request.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
            file_path = self.output_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Calculate file info
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            
            return {
                "file_path": str(file_path),
                "file_size": file_size,
                "file_hash": file_hash,
                "format": ReportFormat.HTML.value
            }
            
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            raise
    
    async def _generate_pdf_report(self, data: Dict[str, Any], request: ReportRequest,
                                 template_config: ReportTemplate) -> Dict[str, Any]:
        """Generate PDF report."""
        try:
            # First generate HTML
            html_result = await self._generate_html_report(data, request, template_config)
            
            # Convert HTML to PDF using weasyprint (if available)
            try:
                import weasyprint
                
                # Read HTML content
                with open(html_result["file_path"], 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                # Generate PDF
                pdf_filename = f"report_{request.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
                pdf_path = self.output_dir / pdf_filename
                
                # Configure PDF generation
                html_doc = weasyprint.HTML(string=html_content)
                css = weasyprint.CSS(string="""
                    @page {
                        size: A4;
                        margin: 2cm;
                        @top-center {
                            content: "PII De-identification System Report";
                            font-size: 10px;
                            color: #666;
                        }
                        @bottom-center {
                            content: "Page " counter(page) " of " counter(pages);
                            font-size: 10px;
                            color: #666;
                        }
                    }
                    body { font-family: Arial, sans-serif; }
                    .no-print { display: none; }
                """)
                
                html_doc.write_pdf(str(pdf_path), stylesheets=[css])
                
                # Clean up temporary HTML file
                Path(html_result["file_path"]).unlink()
                
                # Calculate file info
                file_size = pdf_path.stat().st_size
                file_hash = self._calculate_file_hash(pdf_path)
                
                return {
                    "file_path": str(pdf_path),
                    "file_size": file_size,
                    "file_hash": file_hash,
                    "format": ReportFormat.PDF.value
                }
                
            except ImportError:
                logger.warning("weasyprint not available, falling back to HTML report")
                return {
                    **html_result,
                    "format": ReportFormat.HTML.value,
                    "note": "PDF generation not available, generated HTML instead"
                }
            
        except Exception as e:
            logger.error(f"PDF report generation failed: {e}")
            raise
    
    async def _generate_excel_report(self, data: Dict[str, Any], request: ReportRequest,
                                   template_config: ReportTemplate) -> Dict[str, Any]:
        """Generate Excel report."""
        try:
            filename = f"report_{request.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
            file_path = self.output_dir / filename
            
            with pd.ExcelWriter(str(file_path), engine='openpyxl') as writer:
                # Summary sheet
                summary_df = self._create_summary_dataframe(data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                
                # Events sheet (if available)
                if 'events' in data and data['events']:
                    events_df = pd.DataFrame(data['events'])
                    # Limit rows for Excel (Excel has 1M row limit)
                    if len(events_df) > 100000:
                        events_df = events_df.head(100000)
                        logger.warning(f"Limited Excel export to 100,000 events (was {len(data['events'])})")
                    
                    events_df.to_excel(writer, sheet_name='Events', index=False)
                
                # Charts data sheet
                if 'charts' in data:
                    charts_df = self._create_charts_dataframe(data['charts'])
                    charts_df.to_excel(writer, sheet_name='Charts_Data', index=False)
                
                # Security insights sheet
                if 'security_insights' in data and data['security_insights']:
                    insights_df = pd.DataFrame(data['security_insights'])
                    insights_df.to_excel(writer, sheet_name='Security_Insights', index=False)
                
                # Format worksheets
                self._format_excel_worksheets(writer)
            
            # Calculate file info
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            
            return {
                "file_path": str(file_path),
                "file_size": file_size,
                "file_hash": file_hash,
                "format": ReportFormat.EXCEL.value
            }
            
        except Exception as e:
            logger.error(f"Excel report generation failed: {e}")
            raise
    
    async def _generate_json_report(self, data: Dict[str, Any], request: ReportRequest,
                                  template_config: ReportTemplate) -> Dict[str, Any]:
        """Generate JSON report."""
        try:
            # Prepare JSON data
            json_data = {
                "report_metadata": {
                    "id": str(request.id),
                    "type": request.report_type.value,
                    "title": request.title,
                    "generated_at": datetime.utcnow().isoformat(),
                    "time_range": {
                        "start": request.start_date.isoformat(),
                        "end": request.end_date.isoformat()
                    },
                    "filters": request.filters,
                    "requested_by": str(request.requested_by)
                },
                "data": data
            }
            
            filename = f"report_{request.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            file_path = self.output_dir / filename
            
            # Write JSON with pretty formatting
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
            
            # Calculate file info
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            
            return {
                "file_path": str(file_path),
                "file_size": file_size,
                "file_hash": file_hash,
                "format": ReportFormat.JSON.value
            }
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            raise
    
    async def _generate_csv_report(self, data: Dict[str, Any], request: ReportRequest,
                                 template_config: ReportTemplate) -> Dict[str, Any]:
        """Generate CSV report."""
        try:
            filename = f"report_{request.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            file_path = self.output_dir / filename
            
            # Convert main data to CSV
            if 'events' in data and data['events']:
                events_df = pd.DataFrame(data['events'])
                events_df.to_csv(file_path, index=False, encoding='utf-8')
            else:
                # Create summary CSV if no events data
                summary_df = self._create_summary_dataframe(data)
                summary_df.to_csv(file_path, index=False, encoding='utf-8')
            
            # Calculate file info
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            
            return {
                "file_path": str(file_path),
                "file_size": file_size,
                "file_hash": file_hash,
                "format": ReportFormat.CSV.value
            }
            
        except Exception as e:
            logger.error(f"CSV report generation failed: {e}")
            raise
    
    def _create_summary_dataframe(self, data: Dict[str, Any]) -> pd.DataFrame:
        """Create summary DataFrame from report data."""
        summary_items = []
        
        if 'summary' in data:
            for key, value in data['summary'].items():
                summary_items.append({
                    'Metric': key.replace('_', ' ').title(),
                    'Value': str(value)
                })
        
        if 'metadata' in data:
            summary_items.append({
                'Metric': 'Report Generated',
                'Value': data['metadata'].get('generated_at', 'Unknown')
            })
            summary_items.append({
                'Metric': 'Data Points',
                'Value': str(data['metadata'].get('data_points', 0))
            })
        
        return pd.DataFrame(summary_items)
    
    def _create_charts_dataframe(self, charts_data: Dict[str, Any]) -> pd.DataFrame:
        """Create DataFrame from charts data."""
        chart_rows = []
        
        for chart_name, chart_info in charts_data.items():
            if 'data' in chart_info:
                chart_data = chart_info['data']
                labels = chart_data.get('labels', [])
                values = chart_data.get('values', [])
                
                for label, value in zip(labels, values):
                    chart_rows.append({
                        'Chart': chart_name,
                        'Label': label,
                        'Value': value
                    })
        
        return pd.DataFrame(chart_rows)
    
    def _format_excel_worksheets(self, writer):
        """Format Excel worksheets with styling."""
        try:
            from openpyxl.styles import Font, Fill, PatternFill, Alignment
            
            # Style headers
            header_font = Font(bold=True, color="FFFFFF")
            header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                
                # Format header row
                for cell in worksheet[1]:
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = Alignment(horizontal="center")
                
                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
                    
        except ImportError:
            logger.warning("openpyxl styling not available")
        except Exception as e:
            logger.warning(f"Excel formatting failed: {e}")
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def create_custom_template(self, template_config: ReportTemplate) -> str:
        """Create a custom report template."""
        template_path = self.templates_dir / template_config.template_file
        
        # Create basic HTML template if it doesn't exist
        if not template_path.exists():
            basic_template = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: {{ primary_color }}; color: white; padding: 20px; }
        .summary { margin: 20px 0; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .table th { background-color: {{ header_bg }}; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated on {{ generated_at | format_datetime }}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        {% if report_data.summary %}
            <table class="table">
                {% for key, value in report_data.summary.items() %}
                <tr>
                    <td><strong>{{ key | replace('_', ' ') | title }}</strong></td>
                    <td>{{ value }}</td>
                </tr>
                {% endfor %}
            </table>
        {% endif %}
    </div>
    
    {% if report_data.events %}
    <div class="events">
        <h2>Events (showing first 100)</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Severity</th>
                    <th>User</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {% for event in report_data.events[:100] %}
                <tr>
                    <td>{{ event.timestamp | format_datetime }}</td>
                    <td>{{ event.event_type }}</td>
                    <td><span style="color: {{ event.severity | severity_color }}">{{ event.severity }}</span></td>
                    <td>{{ event.username or 'System' }}</td>
                    <td>{{ event.description | truncate_text(100) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
</body>
</html>
            """.strip()
            
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(basic_template)
            
            logger.info(f"Created custom template: {template_path}")
        
        return str(template_path)
    
    def get_supported_formats(self, template_type: TemplateType) -> List[ReportFormat]:
        """Get supported formats for a template type."""
        template_config = self.templates.get(template_type)
        if template_config:
            return template_config.supported_formats
        return [ReportFormat.JSON, ReportFormat.CSV]  # Default formats
    
    def list_available_templates(self) -> List[Dict[str, Any]]:
        """List all available report templates."""
        return [
            {
                "name": config.name,
                "type": config.template_type.value,
                "template_file": config.template_file,
                "supported_formats": [fmt.value for fmt in config.supported_formats]
            }
            for config in self.templates.values()
        ]