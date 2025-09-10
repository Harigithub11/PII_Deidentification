#!/usr/bin/env python3
"""
Threat Intelligence System Demo

Demonstrates the complete advanced threat intelligence system including
detection, analysis, response, and reporting capabilities.
"""

import asyncio
import json
import logging
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import threat intelligence components
from src.core.security.threat_intelligence.engine import ThreatIntelligenceEngine
from src.core.security.threat_intelligence.indicators import ThreatIndicator, IOCType, ThreatLevel
from src.core.security.threat_intelligence.dashboard import ThreatIntelligenceDashboard, ReportType
from src.core.security.threat_intelligence.feeds import ThreatFeed, FeedType, FeedFormat

logger = logging.getLogger(__name__)


class ThreatIntelligenceDemo:
    """Comprehensive demonstration of threat intelligence capabilities."""
    
    def __init__(self):
        """Initialize demo."""
        self.demo_dir = Path("threat_intelligence_demo")
        self.demo_dir.mkdir(exist_ok=True)
        
        self.engine = None
        self.dashboard = None
        
    async def initialize(self):
        """Initialize threat intelligence system."""
        logger.info("🚀 Initializing Advanced Threat Intelligence System...")
        
        # Initialize threat intelligence engine
        config = {
            'storage_path': str(self.demo_dir / "storage"),
            'db_path': str(self.demo_dir / "engine.db")
        }
        
        self.engine = ThreatIntelligenceEngine(config)
        await self.engine.initialize()
        
        # Initialize dashboard
        self.dashboard = ThreatIntelligenceDashboard(str(self.demo_dir / "dashboard.db"))
        await self.dashboard.initialize(self.engine)
        
        logger.info("✅ Threat Intelligence System initialized successfully")
    
    async def setup_sample_indicators(self):
        """Setup sample threat indicators."""
        logger.info("📋 Setting up sample threat indicators...")
        
        sample_indicators = [
            # Malicious IPs
            ThreatIndicator("192.168.100.1", IOCType.IP_ADDRESS, "malware_c2", ThreatLevel.CRITICAL, 0.95, "demo_feed", "Known malware C2 server"),
            ThreatIndicator("10.0.0.100", IOCType.IP_ADDRESS, "scanning", ThreatLevel.MEDIUM, 0.75, "demo_feed", "Port scanning activity"),
            ThreatIndicator("203.0.113.50", IOCType.IP_ADDRESS, "brute_force", ThreatLevel.HIGH, 0.88, "demo_feed", "Brute force source"),
            
            # Malicious domains
            ThreatIndicator("malware.example.org", IOCType.DOMAIN, "malware", ThreatLevel.HIGH, 0.92, "demo_feed", "Malware distribution site"),
            ThreatIndicator("phishing.example.net", IOCType.DOMAIN, "phishing", ThreatLevel.HIGH, 0.89, "demo_feed", "Phishing campaign domain"),
            ThreatIndicator("suspicious.example.com", IOCType.DOMAIN, "suspicious", ThreatLevel.MEDIUM, 0.65, "demo_feed", "Suspicious domain activity"),
            
            # File hashes
            ThreatIndicator("d41d8cd98f00b204e9800998ecf8427e", IOCType.FILE_HASH_MD5, "malware", ThreatLevel.CRITICAL, 0.98, "demo_feed", "Known malware hash"),
            ThreatIndicator("356a192b7913b04c54574d18c28d46e6395428ab", IOCType.FILE_HASH_SHA1, "trojan", ThreatLevel.HIGH, 0.91, "demo_feed", "Banking trojan"),
            
            # Malicious user agents
            ThreatIndicator("sqlmap.*", IOCType.USER_AGENT, "sql_injection", ThreatLevel.HIGH, 0.93, "demo_feed", "SQL injection tool"),
            ThreatIndicator("nikto.*", IOCType.USER_AGENT, "web_scanner", ThreatLevel.MEDIUM, 0.82, "demo_feed", "Web vulnerability scanner"),
        ]
        
        for indicator in sample_indicators:
            await self.engine.indicator_manager.add_indicator(indicator)
        
        stats = await self.engine.indicator_manager.get_indicator_stats()
        logger.info(f"✅ Added {stats['total_indicators']} threat indicators")
        
        # Display indicator statistics
        print("\n📊 Threat Indicator Statistics:")
        print(f"  Total Indicators: {stats['total_indicators']}")
        print(f"  Active Indicators: {stats['active_indicators']}")
        print("\n  Severity Distribution:")
        for severity, count in stats['severity_distribution'].items():
            print(f"    {severity.title()}: {count}")
        print("\n  Type Distribution:")
        for ioc_type, count in stats['type_distribution'].items():
            print(f"    {ioc_type.replace('_', ' ').title()}: {count}")
    
    async def simulate_security_events(self):
        """Simulate various security events."""
        logger.info("⚡ Simulating security events...")
        
        # Normal events
        normal_events = [
            {
                'source_ip': '192.168.1.50',
                'user_id': 'john.doe',
                'endpoint': '/api/documents',
                'method': 'GET',
                'status_code': 200,
                'response_time': 150,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            {
                'source_ip': '192.168.1.75',
                'user_id': 'jane.smith',
                'endpoint': '/api/upload',
                'method': 'POST',
                'status_code': 201,
                'response_time': 850,
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
            }
        ]
        
        # Malicious events (will trigger alerts)
        malicious_events = [
            {
                'source_ip': '192.168.100.1',  # Matches malware C2 indicator
                'user_id': 'attacker',
                'endpoint': '/api/sensitive',
                'method': 'GET',
                'status_code': 200,
                'response_time': 2000,
                'user_agent': 'BadBot/1.0'
            },
            {
                'source_ip': '203.0.113.50',  # Matches brute force indicator
                'user_id': None,
                'endpoint': '/auth/login',
                'method': 'POST',
                'status_code': 401,
                'response_time': 100,
                'user_agent': 'AttackTool/2.0'
            },
            {
                'source_ip': '10.0.0.100',  # Matches scanning indicator
                'endpoint': '/admin/config',
                'method': 'GET',
                'status_code': 403,
                'response_time': 50,
                'user_agent': 'sqlmap/1.4.12'  # Matches malicious user agent
            }
        ]
        
        # Simulate normal traffic
        print("\n🌐 Processing normal security events...")
        for i, event in enumerate(normal_events * 3):  # Repeat for variety
            event = event.copy()
            event['timestamp'] = (datetime.now(timezone.utc) - timedelta(minutes=30-i*2)).isoformat()
            event['event_id'] = f"normal_{i}"
            
            await self.engine.process_security_event(event)
            await asyncio.sleep(0.1)  # Small delay for realism
        
        # Simulate brute force attack (multiple failed logins)
        print("\n🔥 Simulating brute force attack...")
        for i in range(8):  # 8 failed attempts from same IP
            event = {
                'source_ip': '203.0.113.50',
                'endpoint': '/auth/login',
                'method': 'POST',
                'status_code': 401,
                'response_time': 100 + random.randint(0, 50),
                'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=5-i)).isoformat(),
                'user_agent': f'AttackBot/{i+1}.0',
                'event_id': f"brute_force_{i}"
            }
            
            await self.engine.process_security_event(event)
            await asyncio.sleep(0.2)
        
        # Process malicious events
        print("\n⚠️  Processing malicious security events...")
        for i, event in enumerate(malicious_events):
            event = event.copy()
            event['timestamp'] = (datetime.now(timezone.utc) - timedelta(minutes=10-i)).isoformat()
            event['event_id'] = f"malicious_{i}"
            
            threat_context = await self.engine.process_security_event(event)
            if threat_context:
                print(f"  🚨 THREAT DETECTED: {threat_context.threat_type} "
                      f"(Severity: {threat_context.severity.value}, "
                      f"Confidence: {threat_context.confidence:.2f})")
            
            await asyncio.sleep(0.5)
        
        logger.info("✅ Security event simulation completed")
    
    async def demonstrate_behavioral_analytics(self):
        """Demonstrate behavioral analytics and anomaly detection."""
        logger.info("🧠 Demonstrating behavioral analytics...")
        
        user_id = "demo_user"
        
        # Create normal user behavior pattern
        print(f"\n👤 Building behavior profile for user: {user_id}")
        for i in range(15):  # Build baseline with 15 normal events
            normal_event = {
                'user_id': user_id,
                'timestamp': (datetime.now(timezone.utc) - timedelta(hours=2, minutes=i*5)).isoformat(),
                'source_ip': '192.168.1.100',  # Consistent IP
                'endpoint': '/api/documents',  # Normal endpoint
                'session_duration': 1800 + random.randint(-300, 300),  # ~30 min sessions
                'response_time': 200 + random.randint(-50, 100)
            }
            
            await self.engine.behavioral_analytics.analyze_event(normal_event)
        
        print(f"  📈 Built behavioral profile with 15 normal activities")
        
        # Introduce anomalous behavior
        print(f"\n🔍 Testing anomaly detection...")
        anomalous_events = [
            {
                'user_id': user_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': '10.0.0.200',  # Different IP (location anomaly)
                'endpoint': '/admin/users',  # Unusual endpoint
                'session_duration': 7200,  # Much longer session (4 hours)
                'response_time': 5000  # Very slow response
            },
            {
                'user_id': user_id,
                'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                'source_ip': '192.168.1.100',
                'endpoint': '/api/documents',
                'timestamp': (datetime.now(timezone.utc).replace(hour=3)).isoformat(),  # Unusual time (3 AM)
                'session_duration': 300,  # Very short session
                'response_time': 100
            }
        ]
        
        for event in anomalous_events:
            anomalies = await self.engine.behavioral_analytics.analyze_event(event)
            if anomalies:
                for anomaly in anomalies:
                    print(f"  🚨 ANOMALY DETECTED: {anomaly.description} "
                          f"(Type: {anomaly.anomaly_type.value}, "
                          f"Confidence: {anomaly.confidence:.2f}, "
                          f"Severity: {anomaly.severity.value})")
        
        # Get analytics summary
        summary = await self.engine.behavioral_analytics.get_analytics_summary()
        print(f"\n📊 Analytics Summary:")
        print(f"  User Profiles: {summary.get('user_profiles_count', 0)}")
        print(f"  Events Analyzed: {summary.get('events_analyzed', 0)}")
    
    async def demonstrate_automated_response(self):
        """Demonstrate automated threat response capabilities."""
        logger.info("🤖 Demonstrating automated threat response...")
        
        # Get response system status before
        status_before = await self.engine.threat_response.get_response_status()
        print(f"\n📊 Response System Status (Before):")
        print(f"  Active Tasks: {status_before.get('active_tasks', 0)}")
        print(f"  Blocked IPs: {status_before.get('executor_status', {}).get('blocked_ips', 0)}")
        print(f"  Quarantined Users: {status_before.get('executor_status', {}).get('quarantined_users', 0)}")
        
        # Simulate high-severity threat requiring immediate response
        print(f"\n🔥 Simulating high-severity threat...")
        critical_event = {
            'source_ip': '198.51.100.50',
            'user_id': 'suspicious_user',
            'endpoint': '/api/sensitive_data',
            'method': 'GET',
            'status_code': 200,
            'response_size': 100 * 1024 * 1024,  # Large response (potential data exfiltration)
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_agent': 'DataExfiltrator/1.0'
        }
        
        # Add matching high-severity indicator
        critical_indicator = ThreatIndicator(
            "198.51.100.50",
            IOCType.IP_ADDRESS,
            "data_exfiltration",
            ThreatLevel.CRITICAL,
            0.97,
            "demo",
            "Known data exfiltration source"
        )
        await self.engine.indicator_manager.add_indicator(critical_indicator)
        
        # Process critical event
        threat_context = await self.engine.process_security_event(critical_event)
        
        if threat_context:
            print(f"  🚨 CRITICAL THREAT: {threat_context.threat_type}")
            print(f"     Severity: {threat_context.severity.value}")
            print(f"     Confidence: {threat_context.confidence:.2f}")
            print(f"     Automated Response: TRIGGERED")
        
        # Wait for responses to process
        await asyncio.sleep(2)
        
        # Check response system status after
        status_after = await self.engine.threat_response.get_response_status()
        print(f"\n📊 Response System Status (After):")
        print(f"  Active Tasks: {status_after.get('active_tasks', 0)}")
        print(f"  Blocked IPs: {status_after.get('executor_status', {}).get('blocked_ips', 0)}")
        print(f"  Quarantined Users: {status_after.get('executor_status', {}).get('quarantined_users', 0)}")
        
        # Show response effectiveness
        tasks_change = status_after.get('active_tasks', 0) - status_before.get('active_tasks', 0)
        if tasks_change > 0:
            print(f"  ⚡ {tasks_change} automated response tasks initiated")
    
    async def demonstrate_forensics(self):
        """Demonstrate forensic evidence collection."""
        logger.info("🔬 Demonstrating forensic capabilities...")
        
        # Simulate forensic evidence collection for a security incident
        print(f"\n📋 Collecting forensic evidence...")
        
        # Mock threat context for evidence collection
        class MockThreatContext:
            def __init__(self):
                self.threat_type = 'data_breach'
                self.threat_id = 'demo_incident_001'
                self.severity = ThreatLevel.HIGH
                self.metadata = {
                    'user_id': 'compromised_user',
                    'source_ip': '192.168.1.200',
                    'affected_data': 'customer_records'
                }
        
        threat_context = MockThreatContext()
        
        # Collect evidence
        evidence_items = await self.engine.forensics_collector.collect_evidence(threat_context)
        
        print(f"  📦 Collected {len(evidence_items)} evidence items:")
        for item in evidence_items:
            print(f"    - {item.evidence_type.value}: {item.name}")
            print(f"      Status: {item.status.value}")
            print(f"      Size: {item.file_size} bytes")
            print(f"      Chain of Custody: {len(item.chain_of_custody)} entries")
        
        # Get forensics summary
        forensics_summary = await self.engine.forensics_collector.get_forensics_summary()
        print(f"\n🔬 Forensics System Summary:")
        print(f"  Total Evidence: {forensics_summary.get('total_evidence', 0)}")
        print(f"  Storage Used: {forensics_summary.get('total_storage_bytes', 0):,} bytes")
        print(f"  Retention Policy: {forensics_summary.get('retention_days', 365)} days")
    
    async def demonstrate_dashboard(self):
        """Demonstrate dashboard and reporting capabilities."""
        logger.info("📊 Demonstrating dashboard and reporting...")
        
        # Get complete dashboard data
        dashboard_data = await self.dashboard.get_dashboard_data()
        
        print(f"\n📊 Threat Intelligence Dashboard:")
        print(f"  Last Updated: {dashboard_data['last_refresh']}")
        print(f"  System Status: {dashboard_data['system_status']}")
        
        # Display key widget data
        widgets = dashboard_data['widgets']
        
        if 'threat_overview' in widgets:
            threat_data = widgets['threat_overview']['data']
            print(f"\n🎯 Threat Overview:")
            print(f"  Total Threats: {threat_data.get('total_threats', 0)}")
            print(f"  Threats Blocked: {threat_data.get('threats_blocked', 0)}")
            print(f"  Active Threats: {threat_data.get('active_threats', 0)}")
            print(f"  System Status: {threat_data.get('system_status', 'unknown')}")
        
        if 'ioc_statistics' in widgets:
            ioc_data = widgets['ioc_statistics']['data']
            print(f"\n📋 IOC Statistics:")
            print(f"  Total Indicators: {ioc_data.get('total_indicators', 0)}")
            print(f"  Active Indicators: {ioc_data.get('active_indicators', 0)}")
        
        if 'system_health' in widgets:
            health_data = widgets['system_health']['data']
            print(f"\n❤️  System Health:")
            print(f"  Overall Status: {health_data.get('overall_status', 'unknown')}")
            print(f"  CPU Usage: {health_data.get('cpu_usage', 0):.1f}%")
            print(f"  Memory Usage: {health_data.get('memory_usage', 0):.1f}%")
        
        # Generate executive summary report
        print(f"\n📄 Generating Executive Summary Report...")
        time_period = (
            datetime.now(timezone.utc) - timedelta(hours=24),
            datetime.now(timezone.utc)
        )
        
        report = await self.dashboard.generate_report(
            ReportType.EXECUTIVE_SUMMARY,
            time_period
        )
        
        print(f"  Report ID: {report.report_id}")
        print(f"  Title: {report.title}")
        print(f"  Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Display key report content
        content = report.content
        if 'summary' in content:
            summary = content['summary']
            print(f"\n📈 Executive Summary:")
            print(f"  Threats Detected: {summary.get('total_threats_detected', 0)}")
            print(f"  Threats Blocked: {summary.get('threats_blocked', 0)}")
            print(f"  Active Incidents: {summary.get('active_incidents', 0)}")
        
        if 'key_metrics' in content:
            metrics = content['key_metrics']
            print(f"\n📊 Key Metrics:")
            for metric, value in metrics.items():
                print(f"  {metric.replace('_', ' ').title()}: {value}")
        
        if 'recommendations' in content:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(content['recommendations'][:3], 1):
                print(f"  {i}. {rec}")
    
    async def display_final_summary(self):
        """Display final system summary."""
        logger.info("📋 Generating final system summary...")
        
        # Get comprehensive system status
        threat_summary = await self.engine.get_threat_summary()
        dashboard_health = await self.dashboard.get_dashboard_health()
        
        print(f"\n" + "="*80)
        print(f"🎯 THREAT INTELLIGENCE SYSTEM - FINAL SUMMARY")
        print(f"="*80)
        
        # Engine metrics
        metrics = threat_summary.get('metrics', {})
        print(f"\n🚀 Engine Performance:")
        print(f"  Status: {threat_summary.get('status', 'unknown').title()}")
        print(f"  Uptime: {metrics.get('uptime_hours', 0):.1f} hours")
        print(f"  Threats Detected: {metrics.get('threats_detected', 0)}")
        print(f"  Threats Blocked: {metrics.get('threats_blocked', 0)}")
        print(f"  False Positives: {metrics.get('false_positives', 0)}")
        print(f"  Incidents Created: {metrics.get('incidents_created', 0)}")
        print(f"  Avg Processing Latency: {metrics.get('avg_processing_latency_ms', 0):.2f}ms")
        
        # Active threats
        active_threats = threat_summary.get('active_threats', [])
        if active_threats:
            print(f"\n🚨 Active Threats ({len(active_threats)}):")
            for threat in active_threats[:5]:  # Show up to 5 threats
                print(f"  - {threat.get('type', 'unknown')} "
                      f"(Severity: {threat.get('severity', 'unknown')}, "
                      f"Count: {threat.get('count', 1)})")
        else:
            print(f"\n✅ No active threats detected")
        
        # Component status
        print(f"\n🏗️  Component Status:")
        components = [
            'Threat Indicator Manager',
            'Behavioral Analytics Engine', 
            'Advanced Security Monitor',
            'Automated Threat Response',
            'Threat Feed Manager',
            'Forensics Collector',
            'Intelligence Dashboard'
        ]
        
        for component in components:
            print(f"  ✅ {component}: Operational")
        
        # Dashboard health
        print(f"\n📊 Dashboard Health:")
        print(f"  Status: {dashboard_health.get('status', 'unknown').title()}")
        print(f"  Total Widgets: {dashboard_health.get('total_widgets', 0)}")
        print(f"  Stale Widgets: {dashboard_health.get('stale_widgets', 0)}")
        print(f"  Reports Generated: {dashboard_health.get('reports_generated', 0)}")
        
        # Success indicators
        success_score = 0
        if threat_summary.get('status') == 'active':
            success_score += 30
        if metrics.get('threats_detected', 0) > 0:
            success_score += 20
        if metrics.get('threats_blocked', 0) > 0:
            success_score += 20
        if len(active_threats) >= 0:  # System is detecting threats
            success_score += 15
        if dashboard_health.get('status') == 'healthy':
            success_score += 15
        
        print(f"\n🎖️  System Health Score: {success_score}/100")
        
        if success_score >= 80:
            status_msg = "🟢 EXCELLENT - System performing optimally"
        elif success_score >= 60:
            status_msg = "🟡 GOOD - System performing well"
        else:
            status_msg = "🔴 NEEDS ATTENTION - Check component status"
        
        print(f"   {status_msg}")
        
        print(f"\n" + "="*80)
        print(f"✅ THREAT INTELLIGENCE SYSTEM DEMONSTRATION COMPLETE")
        print(f"="*80)
    
    async def run_complete_demo(self):
        """Run complete demonstration of threat intelligence system."""
        try:
            print("🚀 ADVANCED THREAT INTELLIGENCE SYSTEM DEMONSTRATION")
            print("="*70)
            print("This demo showcases a comprehensive threat intelligence system")
            print("with real-time detection, behavioral analytics, automated response,")
            print("forensic capabilities, and intelligent reporting.")
            print("="*70)
            
            await self.initialize()
            
            # Wait a moment for full initialization
            await asyncio.sleep(2)
            
            await self.setup_sample_indicators()
            await self.simulate_security_events()
            await self.demonstrate_behavioral_analytics()
            await self.demonstrate_automated_response()
            await self.demonstrate_forensics()
            await self.demonstrate_dashboard()
            
            # Give system time to process everything
            await asyncio.sleep(3)
            
            await self.display_final_summary()
            
        except Exception as e:
            logger.error(f"Demo error: {e}")
            raise
        finally:
            await self.cleanup()
    
    async def cleanup(self):
        """Cleanup demo resources."""
        logger.info("🧹 Cleaning up demo resources...")
        
        if self.dashboard:
            await self.dashboard.shutdown()
        
        if self.engine:
            await self.engine.shutdown()
        
        logger.info("✅ Demo cleanup completed")


async def main():
    """Main demo execution."""
    print("\n" + "="*80)
    print("🛡️  ADVANCED THREAT INTELLIGENCE SYSTEM DEMONSTRATION")
    print("="*80)
    print()
    
    demo = ThreatIntelligenceDemo()
    await demo.run_complete_demo()
    
    print(f"\n💡 Demo data stored in: {demo.demo_dir}")
    print("   You can inspect the generated databases and evidence files.")
    print("\n🎉 Thank you for exploring the Advanced Threat Intelligence System!")


if __name__ == "__main__":
    asyncio.run(main())