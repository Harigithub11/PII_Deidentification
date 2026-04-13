"""
PCI DSS API Endpoints

This module provides REST API endpoints for PCI DSS compliance management.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

from ..core.compliance.pci_dss_core import PCIDSSComplianceEngine
from ..core.compliance.card_data_protection import CardDataProtectionManager, CardDataType, EncryptionAlgorithm
from ..core.compliance.network_security import NetworkSecurityManager, VulnerabilityLevel
from ..core.compliance.access_control import AccessControlManager, UserRole, Permission
from ..core.compliance.monitoring_system import SecurityMonitoringSystem, EventType, Severity
from ..core.database.database_manager import DatabaseManager
from ..core.security.encryption import EncryptionManager

logger = logging.getLogger(__name__)

# Initialize router
pci_dss_router = APIRouter(prefix="/api/v1/pci-dss", tags=["PCI DSS Compliance"])

# Security dependency
security = HTTPBearer()

# Pydantic models for API requests/responses
class ComplianceAssessmentRequest(BaseModel):
    """Request model for compliance assessment."""
    scope: Optional[List[str]] = Field(default=None, description="Assessment scope")
    requirements: Optional[List[str]] = Field(default=None, description="Specific requirements to assess")

class ComplianceAssessmentResponse(BaseModel):
    """Response model for compliance assessment."""
    assessment_id: str
    overall_status: str
    compliance_score: float
    requirements: List[Dict[str, Any]]
    recommendations: List[str]
    assessment_date: datetime

class CardDataDetectionRequest(BaseModel):
    """Request model for card data detection."""
    text: str = Field(..., description="Text to scan for card data")
    detection_rules: Optional[Dict[str, Any]] = Field(default=None)

class CardDataDetectionResponse(BaseModel):
    """Response model for card data detection."""
    detected_data: List[Dict[str, Any]]
    risk_level: str
    recommendations: List[str]

class EncryptionRequest(BaseModel):
    """Request model for data encryption."""
    data_type: CardDataType
    value: str
    algorithm: Optional[EncryptionAlgorithm] = EncryptionAlgorithm.AES_256_GCM

class EncryptionResponse(BaseModel):
    """Response model for data encryption."""
    success: bool
    encrypted: bool
    key_id: Optional[str]
    message: str

class VulnerabilityScanRequest(BaseModel):
    """Request model for vulnerability scanning."""
    target_hosts: Optional[List[str]] = Field(default=None)
    scan_type: str = Field(default="comprehensive")

class VulnerabilityScanResponse(BaseModel):
    """Response model for vulnerability scanning."""
    scan_id: str
    status: str
    targets: List[str]
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

class UserCreationRequest(BaseModel):
    """Request model for user creation."""
    username: str
    email: str
    full_name: str
    role: UserRole
    password: str

class UserCreationResponse(BaseModel):
    """Response model for user creation."""
    user_id: str
    username: str
    role: UserRole
    status: str
    created_at: datetime

class AuthenticationRequest(BaseModel):
    """Request model for user authentication."""
    username: str
    password: str

class AuthenticationResponse(BaseModel):
    """Response model for user authentication."""
    success: bool
    session_id: Optional[str]
    user_id: Optional[str]
    expires_at: Optional[datetime]
    message: str

class SecurityEventRequest(BaseModel):
    """Request model for logging security events."""
    event_type: EventType
    user_id: Optional[str]
    resource: str
    action: str
    outcome: str
    description: str
    additional_data: Optional[Dict[str, Any]] = None

class SecurityDashboardResponse(BaseModel):
    """Response model for security dashboard."""
    timestamp: datetime
    summary: Dict[str, int]
    event_statistics: Dict[str, int]
    active_alerts: List[Dict[str, Any]]
    recent_high_risk_events: List[Dict[str, Any]]
    system_metrics: Dict[str, Any]

class AlertResponse(BaseModel):
    """Response model for security alerts."""
    alert_id: str
    status: str
    message: str

# Dependency injection
async def get_compliance_engine() -> PCIDSSComplianceEngine:
    """Get compliance engine instance."""
    # This would be injected from the main application
    return PCIDSSComplianceEngine(
        db_manager=DatabaseManager(),
        encryption_manager=EncryptionManager()
    )

async def get_card_protection_manager() -> CardDataProtectionManager:
    """Get card data protection manager instance."""
    return CardDataProtectionManager(
        db_manager=DatabaseManager(),
        encryption_manager=EncryptionManager(),
        compliance_engine=await get_compliance_engine()
    )

async def get_network_security_manager() -> NetworkSecurityManager:
    """Get network security manager instance."""
    return NetworkSecurityManager(
        db_manager=DatabaseManager(),
        compliance_engine=await get_compliance_engine()
    )

async def get_access_control_manager() -> AccessControlManager:
    """Get access control manager instance."""
    return AccessControlManager(
        db_manager=DatabaseManager(),
        compliance_engine=await get_compliance_engine()
    )

async def get_monitoring_system() -> SecurityMonitoringSystem:
    """Get security monitoring system instance."""
    return SecurityMonitoringSystem(
        db_manager=DatabaseManager(),
        compliance_engine=await get_compliance_engine()
    )

# Helper function to get client info
def get_client_info(request: Request) -> Dict[str, str]:
    """Extract client information from request."""
    return {
        'ip_address': request.client.host if request.client else 'unknown',
        'user_agent': request.headers.get('user-agent', 'unknown')
    }

# Compliance Assessment Endpoints
@pci_dss_router.post("/assessment/run", response_model=ComplianceAssessmentResponse)
async def run_compliance_assessment(
    request: ComplianceAssessmentRequest,
    compliance_engine: PCIDSSComplianceEngine = Depends(get_compliance_engine)
):
    """Run PCI DSS compliance assessment."""
    try:
        # Run comprehensive assessment
        assessment_result = await compliance_engine.run_comprehensive_assessment(
            scope=request.scope,
            requirements=request.requirements
        )
        
        return ComplianceAssessmentResponse(
            assessment_id=assessment_result['assessment_id'],
            overall_status=assessment_result['overall_status'],
            compliance_score=assessment_result['compliance_score'],
            requirements=assessment_result['requirements'],
            recommendations=assessment_result['recommendations'],
            assessment_date=datetime.fromisoformat(assessment_result['assessment_date'])
        )
        
    except Exception as e:
        logger.error(f"Compliance assessment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

@pci_dss_router.get("/assessment/status")
async def get_compliance_status(
    compliance_engine: PCIDSSComplianceEngine = Depends(get_compliance_engine)
):
    """Get current compliance status."""
    try:
        status = await compliance_engine.get_compliance_status()
        return status
        
    except Exception as e:
        logger.error(f"Failed to get compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@pci_dss_router.get("/assessment/history")
async def get_assessment_history(
    limit: int = 10,
    compliance_engine: PCIDSSComplianceEngine = Depends(get_compliance_engine)
):
    """Get compliance assessment history."""
    try:
        history = await compliance_engine.get_assessment_history(limit=limit)
        return {"assessments": history}
        
    except Exception as e:
        logger.error(f"Failed to get assessment history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")

# Card Data Protection Endpoints
@pci_dss_router.post("/card-data/detect", response_model=CardDataDetectionResponse)
async def detect_card_data(
    request: CardDataDetectionRequest,
    card_manager: CardDataProtectionManager = Depends(get_card_protection_manager)
):
    """Detect cardholder data in text."""
    try:
        detected_data = await card_manager.detect_card_data(request.text)
        
        # Determine risk level
        risk_level = "low"
        if detected_data:
            if any(d['type'] == CardDataType.PRIMARY_ACCOUNT_NUMBER for d in detected_data):
                risk_level = "critical"
            elif any(d['type'] == CardDataType.CVV for d in detected_data):
                risk_level = "high"
            else:
                risk_level = "medium"
        
        # Generate recommendations
        recommendations = []
        if detected_data:
            recommendations.append("Cardholder data detected - ensure proper protection")
            recommendations.append("Apply data masking or encryption as required")
            recommendations.append("Review data handling procedures")
        
        return CardDataDetectionResponse(
            detected_data=detected_data,
            risk_level=risk_level,
            recommendations=recommendations
        )
        
    except Exception as e:
        logger.error(f"Card data detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@pci_dss_router.post("/card-data/encrypt", response_model=EncryptionResponse)
async def encrypt_card_data(
    request: EncryptionRequest,
    card_manager: CardDataProtectionManager = Depends(get_card_protection_manager)
):
    """Encrypt cardholder data."""
    try:
        from ..core.compliance.card_data_protection import CardDataElement
        
        # Create card data element
        card_data = CardDataElement(
            data_type=request.data_type,
            value=request.value
        )
        
        # Encrypt the data
        encrypted_data = await card_manager.encrypt_card_data(card_data, request.algorithm)
        
        return EncryptionResponse(
            success=True,
            encrypted=encrypted_data.encrypted,
            key_id=encrypted_data.encryption_key_id,
            message="Data encrypted successfully"
        )
        
    except Exception as e:
        logger.error(f"Data encryption failed: {e}")
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

@pci_dss_router.get("/card-data/compliance")
async def get_card_data_compliance_status(
    card_manager: CardDataProtectionManager = Depends(get_card_protection_manager)
):
    """Get card data protection compliance status."""
    try:
        status = await card_manager.get_compliance_status()
        return status
        
    except Exception as e:
        logger.error(f"Failed to get card data compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

# Network Security Endpoints
@pci_dss_router.post("/network/scan", response_model=VulnerabilityScanResponse)
async def start_vulnerability_scan(
    request: VulnerabilityScanRequest,
    background_tasks: BackgroundTasks,
    network_manager: NetworkSecurityManager = Depends(get_network_security_manager)
):
    """Start vulnerability scan."""
    try:
        # Start scan in background
        scan_result = await network_manager.perform_vulnerability_scan(request.target_hosts)
        
        return VulnerabilityScanResponse(
            scan_id=scan_result['scan_id'],
            status="completed",
            targets=scan_result['targets'],
            vulnerabilities_found=len(scan_result['vulnerabilities']),
            critical_count=scan_result['summary']['critical'],
            high_count=scan_result['summary']['high'],
            medium_count=scan_result['summary']['medium'],
            low_count=scan_result['summary']['low']
        )
        
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@pci_dss_router.get("/network/topology")
async def get_network_topology(
    network_manager: NetworkSecurityManager = Depends(get_network_security_manager)
):
    """Get network topology information."""
    try:
        topology = await network_manager.discover_network_topology()
        return topology
        
    except Exception as e:
        logger.error(f"Failed to get network topology: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get topology: {str(e)}")

@pci_dss_router.get("/network/compliance")
async def get_network_compliance_status(
    network_manager: NetworkSecurityManager = Depends(get_network_security_manager)
):
    """Get network security compliance status."""
    try:
        status = await network_manager.get_compliance_status()
        return status
        
    except Exception as e:
        logger.error(f"Failed to get network compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@pci_dss_router.post("/network/firewall/rules")
async def configure_firewall_rules(
    rules: List[Dict[str, Any]],
    network_manager: NetworkSecurityManager = Depends(get_network_security_manager)
):
    """Configure firewall rules."""
    try:
        result = await network_manager.configure_firewall_rules(rules)
        return result
        
    except Exception as e:
        logger.error(f"Firewall configuration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration failed: {str(e)}")

# Access Control Endpoints
@pci_dss_router.post("/access/users", response_model=UserCreationResponse)
async def create_user(
    request: UserCreationRequest,
    access_manager: AccessControlManager = Depends(get_access_control_manager)
):
    """Create a new user account."""
    try:
        user = await access_manager.create_user(
            username=request.username,
            email=request.email,
            full_name=request.full_name,
            role=request.role,
            password=request.password
        )
        
        return UserCreationResponse(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            status=user.status,
            created_at=user.created_at
        )
        
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise HTTPException(status_code=400, detail=f"User creation failed: {str(e)}")

@pci_dss_router.post("/access/authenticate", response_model=AuthenticationResponse)
async def authenticate_user(
    request: AuthenticationRequest,
    http_request: Request,
    access_manager: AccessControlManager = Depends(get_access_control_manager)
):
    """Authenticate user and create session."""
    try:
        client_info = get_client_info(http_request)
        
        session = await access_manager.authenticate_user(
            username=request.username,
            password=request.password,
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent']
        )
        
        if session:
            return AuthenticationResponse(
                success=True,
                session_id=session.session_id,
                user_id=session.user_id,
                expires_at=session.expires_at,
                message="Authentication successful"
            )
        else:
            return AuthenticationResponse(
                success=False,
                message="Authentication failed"
            )
            
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

@pci_dss_router.get("/access/compliance")
async def get_access_control_compliance_status(
    access_manager: AccessControlManager = Depends(get_access_control_manager)
):
    """Get access control compliance status."""
    try:
        status = await access_manager.get_compliance_status()
        return status
        
    except Exception as e:
        logger.error(f"Failed to get access control compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@pci_dss_router.get("/access/users/{user_id}/activity")
async def get_user_activity_report(
    user_id: str,
    days: int = 30,
    access_manager: AccessControlManager = Depends(get_access_control_manager)
):
    """Get user activity report."""
    try:
        report = await access_manager.get_user_activity_report(user_id, days)
        return report
        
    except Exception as e:
        logger.error(f"Failed to get user activity report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")

# Security Monitoring Endpoints
@pci_dss_router.post("/monitoring/events")
async def log_security_event(
    request: SecurityEventRequest,
    http_request: Request,
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Log a security event."""
    try:
        client_info = get_client_info(http_request)
        
        event = await monitoring_system.log_security_event(
            event_type=request.event_type,
            user_id=request.user_id,
            source_ip=client_info['ip_address'],
            resource=request.resource,
            action=request.action,
            outcome=request.outcome,
            description=request.description,
            additional_data=request.additional_data,
            user_agent=client_info['user_agent']
        )
        
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "message": "Security event logged successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to log event: {str(e)}")

@pci_dss_router.get("/monitoring/dashboard", response_model=SecurityDashboardResponse)
async def get_security_dashboard(
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Get security monitoring dashboard."""
    try:
        dashboard_data = await monitoring_system.get_security_dashboard()
        
        return SecurityDashboardResponse(
            timestamp=datetime.fromisoformat(dashboard_data['timestamp']),
            summary=dashboard_data['summary'],
            event_statistics=dashboard_data['event_statistics'],
            active_alerts=dashboard_data['active_alerts'],
            recent_high_risk_events=dashboard_data['recent_high_risk_events'],
            system_metrics=dashboard_data['system_metrics']
        )
        
    except Exception as e:
        logger.error(f"Failed to get security dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")

@pci_dss_router.get("/monitoring/alerts")
async def get_security_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Get security alerts."""
    try:
        alerts = []
        for alert in list(monitoring_system.security_alerts.values())[:limit]:
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
                
            alerts.append({
                'alert_id': alert.alert_id,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'title': alert.title,
                'description': alert.description,
                'status': alert.status,
                'created_at': alert.created_at.isoformat(),
                'event_count': len(alert.event_ids)
            })
        
        return {"alerts": alerts}
        
    except Exception as e:
        logger.error(f"Failed to get security alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")

@pci_dss_router.post("/monitoring/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    user_id: str,
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Acknowledge a security alert."""
    try:
        success = await monitoring_system.acknowledge_alert(alert_id, user_id)
        
        if success:
            return AlertResponse(
                alert_id=alert_id,
                status="acknowledged",
                message="Alert acknowledged successfully"
            )
        else:
            raise HTTPException(status_code=404, detail="Alert not found or cannot be acknowledged")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge alert: {str(e)}")

@pci_dss_router.post("/monitoring/alerts/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    user_id: str,
    resolution_notes: Optional[str] = None,
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Resolve a security alert."""
    try:
        success = await monitoring_system.resolve_alert(alert_id, user_id, resolution_notes)
        
        if success:
            return AlertResponse(
                alert_id=alert_id,
                status="resolved",
                message="Alert resolved successfully"
            )
        else:
            raise HTTPException(status_code=404, detail="Alert not found or cannot be resolved")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {str(e)}")

@pci_dss_router.get("/monitoring/compliance")
async def get_monitoring_compliance_status(
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Get monitoring compliance status."""
    try:
        status = await monitoring_system.get_compliance_status()
        return status
        
    except Exception as e:
        logger.error(f"Failed to get monitoring compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@pci_dss_router.get("/monitoring/reports/audit")
async def generate_audit_report(
    start_date: datetime,
    end_date: datetime,
    event_types: Optional[List[str]] = None,
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Generate audit report."""
    try:
        # Convert string event types to EventType enum if provided
        event_type_enums = None
        if event_types:
            event_type_enums = [EventType(et) for et in event_types]
        
        report = await monitoring_system.generate_audit_report(
            start_date=start_date,
            end_date=end_date,
            event_types=event_type_enums
        )
        
        return report
        
    except Exception as e:
        logger.error(f"Failed to generate audit report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

# Health Check and Status Endpoints
@pci_dss_router.get("/health")
async def health_check():
    """PCI DSS system health check."""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "compliance_engine": "operational",
                "card_data_protection": "operational",
                "network_security": "operational",
                "access_control": "operational",
                "monitoring_system": "operational"
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@pci_dss_router.get("/status/overview")
async def get_system_overview(
    compliance_engine: PCIDSSComplianceEngine = Depends(get_compliance_engine),
    monitoring_system: SecurityMonitoringSystem = Depends(get_monitoring_system)
):
    """Get overall system status overview."""
    try:
        # Get compliance status
        compliance_status = await compliance_engine.get_compliance_status()
        
        # Get monitoring dashboard
        dashboard = await monitoring_system.get_security_dashboard()
        
        # Compile overview
        overview = {
            "timestamp": datetime.utcnow().isoformat(),
            "compliance": {
                "overall_status": compliance_status.get('overall_status', 'unknown'),
                "compliance_score": compliance_status.get('compliance_score', 0.0),
                "last_assessment": compliance_status.get('last_assessment')
            },
            "security": {
                "total_events_24h": dashboard['summary'].get('total_events_24h', 0),
                "active_alerts": dashboard['summary'].get('active_alerts', 0),
                "critical_alerts": dashboard['summary'].get('critical_alerts', 0),
                "high_risk_events": dashboard['summary'].get('high_risk_events', 0)
            },
            "system_health": "operational"
        }
        
        return overview
        
    except Exception as e:
        logger.error(f"Failed to get system overview: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get overview: {str(e)}")

# Add router to main application
def include_pci_dss_routes(app):
    """Include PCI DSS routes in the main application."""
    app.include_router(pci_dss_router)