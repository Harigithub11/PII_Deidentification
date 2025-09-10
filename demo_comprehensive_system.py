#!/usr/bin/env python3
"""
Comprehensive System Demo

This script demonstrates all the new features of the PII De-identification System v2.0.0:
- Business Intelligence Dashboard System
- Advanced Reporting and Analytics
- Template Management System
- Real-time visualization capabilities
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from uuid import uuid4
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def demo_business_intelligence():
    """Demonstrate Business Intelligence Dashboard functionality."""
    logger.info("=== Business Intelligence Dashboard Demo ===")
    
    try:
        from src.core.dashboard import (
            BusinessIntelligenceEngine, DashboardConfig, DashboardType,
            RefreshInterval, InteractiveDashboard, WidgetConfig, WidgetType,
            VisualizationEngine, ChartType
        )
        
        # Initialize BI Engine
        bi_engine = BusinessIntelligenceEngine()
        logger.info("✅ Business Intelligence Engine initialized")
        
        # Create sample dashboard configuration
        dashboard_config = DashboardConfig(
            name="Security Operations Dashboard",
            description="Real-time security monitoring and threat detection",
            dashboard_type=DashboardType.SECURITY,
            auto_refresh=True,
            refresh_interval=RefreshInterval.THIRTY_SECONDS,
            enable_realtime=True,
            owner_id=uuid4(),
            widgets=[
                {
                    "id": "threat_count",
                    "type": "metric",
                    "title": "Active Threats",
                    "data_source": "security_events",
                    "chart_config": {"color": "#e74c3c"}
                },
                {
                    "id": "processing_chart",
                    "type": "chart",
                    "title": "Document Processing Trends",
                    "data_source": "processing_stats",
                    "chart_type": "line",
                    "chart_config": {"smooth": True}
                },
                {
                    "id": "user_activity",
                    "type": "table",
                    "title": "Recent User Activity",
                    "data_source": "user_events"
                }
            ],
            tags=["security", "monitoring", "real-time"]
        )
        
        # Create dashboard
        created_dashboard = await bi_engine.create_dashboard(dashboard_config)
        logger.info(f"✅ Dashboard created: {created_dashboard.name}")
        
        # Get dashboard data
        dashboard_data = await bi_engine.get_dashboard_data(created_dashboard.id)
        logger.info(f"✅ Retrieved data for {len(dashboard_data['widgets'])} widgets")
        
        # Simulate real-time connection
        connection_id = str(uuid4())
        await bi_engine.register_realtime_connection(created_dashboard.id, connection_id)
        logger.info("✅ Real-time connection established")
        
        # Test visualization engine
        viz_engine = VisualizationEngine()
        
        # Create chart template
        chart_template = viz_engine.create_chart_config_template(
            "security_trend_chart",
            ChartType.LINE,
            title="Security Trends",
            width=800,
            height=400
        )
        logger.info("✅ Chart template created")
        
        # Get performance metrics
        global_metrics = bi_engine.get_global_metrics()
        logger.info(f"✅ BI Engine Metrics: {json.dumps(global_metrics, indent=2)}")
        
        # Clean up
        await bi_engine.unregister_realtime_connection(created_dashboard.id, connection_id)
        await bi_engine.delete_dashboard(created_dashboard.id)
        logger.info("✅ Dashboard demo completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Dashboard demo failed: {e}")
        raise


async def demo_reporting_system():
    """Demonstrate Reporting and Analytics functionality."""
    logger.info("=== Reporting and Analytics Demo ===")
    
    try:
        from src.core.reporting import (
            ReportingEngine, ReportRequest, ReportType, ReportPriority,
            ReportStatus
        )
        
        # Initialize Reporting Engine
        reporting_engine = ReportingEngine()
        logger.info("✅ Reporting Engine initialized")
        
        # Create audit trail report request
        audit_request = ReportRequest(
            report_type=ReportType.AUDIT_TRAIL,
            title="Security Audit Report - Weekly",
            description="Comprehensive security audit for the past week",
            start_date=datetime.utcnow() - timedelta(days=7),
            end_date=datetime.utcnow(),
            filters={
                "severity": "high",
                "event_type": "security"
            },
            output_format="pdf",
            include_details=True,
            include_charts=True,
            priority=ReportPriority.HIGH,
            requested_by=uuid4(),
            compliance_standards=["SOX", "GDPR", "HIPAA"]
        )
        
        # Generate report
        report_result = await reporting_engine.generate_report(audit_request)
        logger.info(f"✅ Audit report generated: {report_result.status}")
        logger.info(f"   - Data points: {report_result.data_points_count}")
        logger.info(f"   - Generation time: {report_result.generation_time_ms}ms")
        
        # Create compliance report
        compliance_request = ReportRequest(
            report_type=ReportType.COMPLIANCE,
            title="GDPR Compliance Report - Monthly",
            description="Monthly GDPR compliance assessment",
            start_date=datetime.utcnow() - timedelta(days=30),
            end_date=datetime.utcnow(),
            filters={
                "compliance_standard": "GDPR"
            },
            output_format="excel",
            requested_by=uuid4(),
            compliance_standards=["GDPR"]
        )
        
        compliance_result = await reporting_engine.generate_report(compliance_request)
        logger.info(f"✅ Compliance report generated: {compliance_result.status}")
        
        # Get active reports
        active_reports = reporting_engine.get_active_reports()
        logger.info(f"✅ Active reports: {len(active_reports)}")
        
        # Get cache statistics
        cache_stats = reporting_engine.get_cache_stats()
        logger.info(f"✅ Cache statistics: {json.dumps(cache_stats, indent=2)}")
        
        logger.info("✅ Reporting demo completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Reporting demo failed: {e}")
        raise


async def demo_template_system():
    """Demonstrate Template Management System functionality."""
    logger.info("=== Template Management System Demo ===")
    
    try:
        from src.core.templates import (
            TemplateEngine, TemplateConfig, TemplateType, TemplateFormat,
            OutputFormat, RenderContext, TemplateManager, TemplateMetadata,
            TemplateCategory
        )
        
        # Initialize Template Engine and Manager
        template_engine = TemplateEngine()
        template_manager = TemplateManager()
        logger.info("✅ Template system initialized")
        
        # Create a Jinja2 template
        template_config = TemplateConfig(
            name="Security Report Template",
            description="Standard template for security audit reports",
            template_type=TemplateType.REPORT,
            template_format=TemplateFormat.JINJA2,
            content="""
<!DOCTYPE html>
<html>
<head>
    <title>{{title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #2c3e50; border-bottom: 2px solid #3498db; }
        .metric { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p>Generated on {{render_time}} by {{user_id}}</p>
    </div>
    
    <div class="metric">
        <h3>Security Summary</h3>
        <p>Total Events: {{total_events|number_format}}</p>
        <p>High Priority: <span class="alert">{{high_priority_events}}</span></p>
        <p>Time Period: {{start_date|datetime_format}} to {{end_date|datetime_format}}</p>
    </div>
    
    <div class="metric">
        <h3>Threat Analysis</h3>
        {% for threat in threats %}
        <p>• {{threat.name}}: {{threat.count}} incidents ({{threat.severity}} severity)</p>
        {% endfor %}
    </div>
    
    <div class="metric">
        <h3>Recommendations</h3>
        {% if high_priority_events > 10 %}
        <p class="alert">⚠️ High number of priority events detected. Immediate review recommended.</p>
        {% endif %}
        <p>📊 Consider implementing additional monitoring for threat patterns.</p>
        <p>🔒 Review access controls and user permissions regularly.</p>
    </div>
</body>
</html>
            """,
            default_values={
                "total_events": 0,
                "high_priority_events": 0,
                "threats": []
            },
            supported_formats=[OutputFormat.HTML, OutputFormat.PDF],
            owner_id=uuid4(),
            category="security",
            tags=["security", "audit", "report"]
        )
        
        # Create template metadata
        template_metadata = TemplateMetadata(
            template_id=template_config.id,
            name=template_config.name,
            description=template_config.description,
            category=TemplateCategory.REPORTS,
            tags=template_config.tags,
            author="Security Team",
            organization="PII De-identification System",
            license="Internal Use",
            documentation="Standard security report template with threat analysis"
        )
        
        # Create template with metadata
        created_config, created_metadata = await template_manager.create_template_with_metadata(
            template_config, template_metadata
        )
        logger.info(f"✅ Template created: {created_config.name}")
        
        # Create version
        await template_manager.create_version(
            created_config.id,
            "1.1.0",
            template_config.content,
            "Added threat analysis section",
            created_config.owner_id
        )
        logger.info("✅ Template version created")
        
        # Render template with sample data
        render_context = RenderContext(
            template_id=created_config.id,
            variables={
                "title": "Weekly Security Audit Report",
                "total_events": 1247,
                "high_priority_events": 23,
                "start_date": datetime.utcnow() - timedelta(days=7),
                "end_date": datetime.utcnow(),
                "threats": [
                    {"name": "Malware Detection", "count": 15, "severity": "High"},
                    {"name": "Unauthorized Access", "count": 8, "severity": "Critical"},
                    {"name": "Data Exfiltration", "count": 3, "severity": "Critical"}
                ]
            },
            output_format=OutputFormat.HTML
        )
        
        render_result = await template_engine.render_template(render_context)
        logger.info(f"✅ Template rendered successfully: {render_result.success}")
        logger.info(f"   - Render time: {render_result.render_time_ms}ms")
        logger.info(f"   - Content length: {len(render_result.content or '')}")
        
        # Search templates
        search_results = template_manager.search_templates(
            query="security",
            category=TemplateCategory.REPORTS,
            tags=["audit"]
        )
        logger.info(f"✅ Found {len(search_results)} templates matching search")
        
        # Export template
        template_package = await template_manager.export_template(
            created_config.id, 
            include_versions=True
        )
        logger.info(f"✅ Template exported: {template_package.getbuffer().nbytes} bytes")
        
        # Get statistics
        engine_stats = template_engine.get_engine_statistics()
        manager_stats = template_manager.get_statistics()
        logger.info(f"✅ Template Engine Stats: {json.dumps(engine_stats, indent=2)}")
        logger.info(f"✅ Template Manager Stats: {json.dumps(manager_stats, indent=2)}")
        
        # Clean up
        await template_manager._template_engine.delete_template(created_config.id)
        logger.info("✅ Template demo completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Template demo failed: {e}")
        raise


async def demo_integration_features():
    """Demonstrate integration features between all systems."""
    logger.info("=== System Integration Demo ===")
    
    try:
        from src.core.dashboard import BusinessIntelligenceEngine, DashboardConfig, DashboardType
        from src.core.reporting import ReportingEngine, ReportRequest, ReportType
        from src.core.templates import TemplateEngine, TemplateConfig, TemplateType
        
        # Initialize all systems
        bi_engine = BusinessIntelligenceEngine()
        reporting_engine = ReportingEngine()
        template_engine = TemplateEngine()
        logger.info("✅ All systems initialized for integration demo")
        
        # Create a dashboard for monitoring report generation
        dashboard_config = DashboardConfig(
            name="Report Generation Monitor",
            description="Monitors report generation and template usage",
            dashboard_type=DashboardType.OPERATIONAL,
            widgets=[
                {
                    "id": "reports_generated",
                    "type": "metric",
                    "title": "Reports Generated Today",
                    "data_source": "report_metrics"
                },
                {
                    "id": "template_usage",
                    "type": "chart",
                    "title": "Template Usage Trends",
                    "data_source": "template_metrics",
                    "chart_type": "bar"
                }
            ],
            owner_id=uuid4()
        )
        
        dashboard = await bi_engine.create_dashboard(dashboard_config)
        logger.info("✅ Integration dashboard created")
        
        # Create a report using the reporting engine
        report_request = ReportRequest(
            report_type=ReportType.PERFORMANCE,
            title="System Performance Report",
            description="Analysis of system performance and usage",
            start_date=datetime.utcnow() - timedelta(hours=24),
            end_date=datetime.utcnow(),
            requested_by=uuid4()
        )
        
        report = await reporting_engine.generate_report(report_request)
        logger.info(f"✅ Performance report generated: {report.status}")
        
        # Create a template for the dashboard summary
        template_config = TemplateConfig(
            name="Dashboard Summary Template",
            description="Template for generating dashboard summaries",
            template_type=TemplateType.DASHBOARD,
            content="<h1>{{dashboard_name}}</h1><p>Widgets: {{widget_count}}</p>",
            owner_id=uuid4()
        )
        
        template = await template_engine.create_template(template_config)
        logger.info("✅ Dashboard template created")
        
        # Simulate data flow between systems
        dashboard_data = await bi_engine.get_dashboard_data(dashboard.id)
        widget_count = len(dashboard_data.get('widgets', {}))
        
        logger.info(f"✅ Data flow demonstration:")
        logger.info(f"   - Dashboard has {widget_count} widgets")
        logger.info(f"   - Report contains {report.data_points_count} data points")
        logger.info(f"   - Template ready for rendering")
        
        # Clean up
        await bi_engine.delete_dashboard(dashboard.id)
        await template_engine.delete_template(template.id)
        
        logger.info("✅ Integration demo completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Integration demo failed: {e}")
        raise


async def main():
    """Main demo function that runs all demonstrations."""
    logger.info("🚀 Starting Comprehensive PII De-identification System v2.0.0 Demo")
    logger.info("=" * 70)
    
    try:
        # Run all demonstrations
        await demo_business_intelligence()
        logger.info("")
        
        await demo_reporting_system()
        logger.info("")
        
        await demo_template_system()
        logger.info("")
        
        await demo_integration_features()
        logger.info("")
        
        logger.info("=" * 70)
        logger.info("🎉 All demonstrations completed successfully!")
        logger.info("")
        logger.info("The PII De-identification System v2.0.0 now includes:")
        logger.info("✅ Business Intelligence Dashboard System with real-time visualization")
        logger.info("✅ Advanced Reporting and Analytics Engine")
        logger.info("✅ Template Management System with visual builder capabilities")
        logger.info("✅ Comprehensive REST API endpoints for web service integration")
        logger.info("✅ Full system integration with existing PII de-identification features")
        logger.info("")
        logger.info("🔗 API Endpoints Available:")
        logger.info("   • Dashboard API: /api/v1/dashboard/")
        logger.info("   • Reporting API: /api/v1/reports/")
        logger.info("   • WebSocket: /api/v1/dashboard/{id}/ws")
        logger.info("   • Documentation: /docs")
        logger.info("")
        logger.info("Ready for production use! 🚀")
        
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())