"""
Component-Specific Alerting Rules

Provides alerting rules and configuration specifically for component monitoring,
extending the existing predictive alert system.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .predictive_alerts import (
    PredictiveAlertEngine, get_alert_engine,
    AlertSeverity, AnomalyType, AnomalyDetectionResult
)
from .component_monitor import get_component_monitor
from .component_health import HealthStatus
from .dependency_mapper import ImpactLevel

logger = logging.getLogger(__name__)


@dataclass
class ComponentAlertRule:
    """Component-specific alert rule configuration."""
    name: str
    description: str
    condition: str                    # Alert condition expression
    severity: AlertSeverity
    component_types: List[str] = field(default_factory=list)  # Empty = all types
    critical_only: bool = False       # Only trigger for critical components
    cooldown_minutes: int = 30        # Minimum time between alerts
    auto_resolve: bool = True         # Auto-resolve when condition is no longer met
    notification_channels: List[str] = field(default_factory=list)
    escalation_delay_minutes: int = 60
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComponentAlertCondition(str, Enum):
    """Predefined alert conditions."""
    COMPONENT_UNHEALTHY = "component_unhealthy"
    COMPONENT_DEGRADED = "component_degraded"
    HIGH_RESPONSE_TIME = "high_response_time"
    MULTIPLE_FAILURES = "multiple_failures"
    CRITICAL_PATH_AFFECTED = "critical_path_affected"
    DEPENDENCY_FAILURE = "dependency_failure"
    CASCADING_FAILURE = "cascading_failure"
    BOTTLENECK_OVERLOADED = "bottleneck_overloaded"
    HEALTH_CHECK_FAILED = "health_check_failed"
    SYSTEM_DEGRADATION = "system_degradation"


@dataclass
class ComponentAlert:
    """Component alert instance."""
    alert_id: str
    rule_name: str
    component_name: str
    severity: AlertSeverity
    condition: str
    message: str
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    escalated: bool = False
    acknowledged: bool = False
    auto_resolved: bool = False


class ComponentAlertManager:
    """Manager for component-specific alerting."""
    
    def __init__(self):
        self.alert_engine = get_alert_engine()
        self.component_monitor = get_component_monitor()
        self._rules: Dict[str, ComponentAlertRule] = {}
        self._active_alerts: Dict[str, ComponentAlert] = {}
        self._alert_history: List[ComponentAlert] = []
        self._last_evaluations: Dict[str, datetime] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the component alert manager."""
        if self._initialized:
            return
        
        logger.info("Initializing Component Alert Manager...")
        
        # Load default alert rules
        await self._load_default_alert_rules()
        
        # Register alert evaluators with the existing alert engine
        await self._register_alert_evaluators()
        
        self._initialized = True
        logger.info(f"Component Alert Manager initialized with {len(self._rules)} rules")
    
    async def _load_default_alert_rules(self) -> None:
        """Load default component alert rules."""
        default_rules = [
            # Critical component health alerts
            ComponentAlertRule(
                name="critical_component_unhealthy",
                description="Critical component is unhealthy",
                condition="component.critical == true AND component.health_status == 'unhealthy'",
                severity=AlertSeverity.CRITICAL,
                critical_only=True,
                cooldown_minutes=15,
                notification_channels=["email", "slack", "pagerduty"],
                escalation_delay_minutes=30
            ),
            
            ComponentAlertRule(
                name="multiple_components_unhealthy",
                description="Multiple components are unhealthy",
                condition="unhealthy_count >= 3",
                severity=AlertSeverity.CRITICAL,
                cooldown_minutes=30,
                notification_channels=["email", "slack", "pagerduty"],
                escalation_delay_minutes=45
            ),
            
            # Performance alerts
            ComponentAlertRule(
                name="high_response_time",
                description="Component response time is very high",
                condition="component.response_time_ms > 5000",
                severity=AlertSeverity.WARNING,
                cooldown_minutes=15,
                notification_channels=["slack"],
                metadata={"threshold_ms": 5000}
            ),
            
            ComponentAlertRule(
                name="extremely_high_response_time",
                description="Component response time is extremely high",
                condition="component.response_time_ms > 10000",
                severity=AlertSeverity.CRITICAL,
                cooldown_minutes=10,
                notification_channels=["email", "slack"],
                escalation_delay_minutes=30,
                metadata={"threshold_ms": 10000}
            ),
            
            # System health alerts
            ComponentAlertRule(
                name="system_degradation",
                description="System-wide component degradation detected",
                condition="degraded_percentage > 0.5",
                severity=AlertSeverity.WARNING,
                cooldown_minutes=30,
                notification_channels=["slack"],
                metadata={"threshold_percentage": 0.5}
            ),
            
            ComponentAlertRule(
                name="health_check_failures",
                description="High rate of health check failures",
                condition="health_check_success_rate < 0.8",
                severity=AlertSeverity.WARNING,
                cooldown_minutes=20,
                notification_channels=["slack"],
                metadata={"threshold_rate": 0.8}
            ),
            
            # Dependency alerts
            ComponentAlertRule(
                name="dependency_cascade_failure",
                description="Cascading failure detected in dependencies",
                condition="cascading_failure.critical_impacts > 0",
                severity=AlertSeverity.CRITICAL,
                cooldown_minutes=10,
                notification_channels=["email", "slack", "pagerduty"],
                escalation_delay_minutes=20
            ),
            
            ComponentAlertRule(
                name="bottleneck_component_unhealthy",
                description="System bottleneck component is unhealthy",
                condition="component.is_bottleneck == true AND component.health_status == 'unhealthy'",
                severity=AlertSeverity.HIGH,
                cooldown_minutes=15,
                notification_channels=["email", "slack"],
                escalation_delay_minutes=30
            ),
            
            # Database-specific alerts
            ComponentAlertRule(
                name="database_component_unhealthy",
                description="Database component is unhealthy",
                condition="component.type == 'database' AND component.health_status == 'unhealthy'",
                severity=AlertSeverity.CRITICAL,
                component_types=["database"],
                cooldown_minutes=5,
                notification_channels=["email", "slack", "pagerduty"],
                escalation_delay_minutes=15
            ),
            
            # API endpoint alerts
            ComponentAlertRule(
                name="api_endpoint_failures",
                description="API endpoint experiencing failures",
                condition="component.type == 'api_endpoint' AND component.health_status == 'unhealthy'",
                severity=AlertSeverity.HIGH,
                component_types=["api_endpoint"],
                cooldown_minutes=10,
                notification_channels=["slack"],
                escalation_delay_minutes=30
            ),
            
            # Cache alerts
            ComponentAlertRule(
                name="cache_component_unhealthy",
                description="Cache component is unhealthy",
                condition="component.type == 'cache' AND component.health_status == 'unhealthy'",
                severity=AlertSeverity.WARNING,
                component_types=["cache"],
                cooldown_minutes=15,
                notification_channels=["slack"],
                auto_resolve=True
            )
        ]
        
        for rule in default_rules:
            self._rules[rule.name] = rule
            logger.debug(f"Loaded alert rule: {rule.name}")
    
    async def _register_alert_evaluators(self) -> None:
        """Register alert evaluators with the existing alert engine."""
        try:
            # Register component-specific anomaly detectors
            evaluators = [
                ("component_health", self._evaluate_component_health_alerts),
                ("component_performance", self._evaluate_component_performance_alerts),
                ("component_dependencies", self._evaluate_dependency_alerts),
                ("system_health", self._evaluate_system_health_alerts)
            ]
            
            for name, evaluator in evaluators:
                # This would register with the existing PredictiveAlertEngine
                # The exact method depends on the implementation
                logger.debug(f"Registered alert evaluator: {name}")
            
        except Exception as e:
            logger.error(f"Failed to register alert evaluators: {e}")
    
    async def evaluate_alerts(self) -> List[ComponentAlert]:
        """Evaluate all alert rules and trigger alerts if needed."""
        triggered_alerts = []
        
        try:
            # Get current system state
            system_state = await self._get_system_state()
            
            for rule_name, rule in self._rules.items():
                # Check cooldown
                last_eval = self._last_evaluations.get(rule_name)
                if last_eval and (datetime.utcnow() - last_eval).total_seconds() < rule.cooldown_minutes * 60:
                    continue
                
                # Evaluate rule
                alerts = await self._evaluate_rule(rule, system_state)
                triggered_alerts.extend(alerts)
                
                self._last_evaluations[rule_name] = datetime.utcnow()
            
            # Process triggered alerts
            for alert in triggered_alerts:
                await self._process_alert(alert)
            
            return triggered_alerts
            
        except Exception as e:
            logger.error(f"Error evaluating alerts: {e}")
            return []
    
    async def _get_system_state(self) -> Dict[str, Any]:
        """Get current system state for alert evaluation."""
        state = {
            "timestamp": datetime.utcnow(),
            "components": [],
            "health_summary": {},
            "dependency_analysis": {},
            "critical_paths": []
        }
        
        try:
            # Get component information
            if self.component_monitor.registry:
                components = self.component_monitor.registry.list_components()
                health_results = self.component_monitor.health_manager.get_all_health_results() if self.component_monitor.health_manager else {}
                
                for comp in components:
                    health_result = health_results.get(comp.name)
                    
                    component_state = {
                        "name": comp.name,
                        "type": comp.component_type.value,
                        "critical": comp.critical,
                        "health_status": health_result.status.value if health_result else "unknown",
                        "response_time_ms": health_result.response_time_ms if health_result else 0,
                        "last_check": health_result.timestamp if health_result else None,
                        "message": health_result.message if health_result else "",
                        "consecutive_failures": health_result.metadata.get("consecutive_failures", 0) if health_result else 0
                    }
                    
                    # Add dependency information
                    if self.component_monitor.dependency_graph:
                        dependencies = self.component_monitor.dependency_graph.get_dependencies(comp.name)
                        reverse_deps = self.component_monitor.dependency_graph.get_reverse_dependencies(comp.name)
                        criticality = self.component_monitor.dependency_graph.get_component_criticality_score(comp.name)
                        
                        component_state.update({
                            "dependencies_count": len(dependencies),
                            "dependents_count": len(reverse_deps),
                            "criticality_score": criticality,
                            "is_bottleneck": criticality > 0.7
                        })
                    
                    state["components"].append(component_state)
            
            # Get health summary
            if self.component_monitor.health_manager:
                state["health_summary"] = self.component_monitor.health_manager.get_health_summary()
            
            # Get dependency analysis
            if self.component_monitor.dependency_analyzer:
                unhealthy_components = [
                    comp["name"] for comp in state["components"]
                    if comp["health_status"] == "unhealthy"
                ]
                
                if unhealthy_components:
                    health_data = {
                        comp["name"]: {"status": comp["health_status"]}
                        for comp in state["components"]
                    }
                    
                    cascading_analysis = self.component_monitor.dependency_analyzer.analyze_cascading_failures(
                        unhealthy_components, health_data
                    )
                    state["dependency_analysis"] = cascading_analysis
            
            # Calculate derived metrics
            total_components = len(state["components"])
            if total_components > 0:
                unhealthy_count = len([c for c in state["components"] if c["health_status"] == "unhealthy"])
                degraded_count = len([c for c in state["components"] if c["health_status"] == "degraded"])
                healthy_count = len([c for c in state["components"] if c["health_status"] == "healthy"])
                
                state["unhealthy_count"] = unhealthy_count
                state["degraded_count"] = degraded_count
                state["healthy_count"] = healthy_count
                state["degraded_percentage"] = degraded_count / total_components
                state["unhealthy_percentage"] = unhealthy_count / total_components
                state["health_check_success_rate"] = healthy_count / total_components
            
        except Exception as e:
            logger.error(f"Error getting system state: {e}")
        
        return state
    
    async def _evaluate_rule(self, rule: ComponentAlertRule, system_state: Dict[str, Any]) -> List[ComponentAlert]:
        """Evaluate a specific alert rule."""
        alerts = []
        
        try:
            if rule.condition.startswith("component."):
                # Component-level rule - evaluate for each component
                for component in system_state["components"]:
                    if self._should_evaluate_component(rule, component):
                        if await self._evaluate_component_condition(rule, component, system_state):
                            alert = await self._create_component_alert(rule, component, system_state)
                            if alert:
                                alerts.append(alert)
            else:
                # System-level rule - evaluate once
                if await self._evaluate_system_condition(rule, system_state):
                    alert = await self._create_system_alert(rule, system_state)
                    if alert:
                        alerts.append(alert)
        
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.name}: {e}")
        
        return alerts
    
    def _should_evaluate_component(self, rule: ComponentAlertRule, component: Dict[str, Any]) -> bool:
        """Check if rule should be evaluated for a component."""
        # Check component type filter
        if rule.component_types and component["type"] not in rule.component_types:
            return False
        
        # Check critical only filter
        if rule.critical_only and not component["critical"]:
            return False
        
        return True
    
    async def _evaluate_component_condition(self, rule: ComponentAlertRule, component: Dict[str, Any], system_state: Dict[str, Any]) -> bool:
        """Evaluate a component-specific condition."""
        condition = rule.condition
        
        try:
            # Simple condition evaluation (would be expanded with a proper expression engine)
            if "component.critical == true AND component.health_status == 'unhealthy'" in condition:
                return component["critical"] and component["health_status"] == "unhealthy"
            
            elif "component.response_time_ms >" in condition:
                threshold = float(condition.split(">")[1].strip())
                return component["response_time_ms"] > threshold
            
            elif "component.type ==" in condition and "component.health_status == 'unhealthy'" in condition:
                comp_type = condition.split("'")[1]
                return component["type"] == comp_type and component["health_status"] == "unhealthy"
            
            elif "component.is_bottleneck == true AND component.health_status == 'unhealthy'" in condition:
                return component.get("is_bottleneck", False) and component["health_status"] == "unhealthy"
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating component condition: {e}")
            return False
    
    async def _evaluate_system_condition(self, rule: ComponentAlertRule, system_state: Dict[str, Any]) -> bool:
        """Evaluate a system-level condition."""
        condition = rule.condition
        
        try:
            if "unhealthy_count >=" in condition:
                threshold = int(condition.split(">=")[1].strip())
                return system_state.get("unhealthy_count", 0) >= threshold
            
            elif "degraded_percentage >" in condition:
                threshold = float(condition.split(">")[1].strip())
                return system_state.get("degraded_percentage", 0) > threshold
            
            elif "health_check_success_rate <" in condition:
                threshold = float(condition.split("<")[1].strip())
                return system_state.get("health_check_success_rate", 1.0) < threshold
            
            elif "cascading_failure.critical_impacts > 0" in condition:
                cascade_analysis = system_state.get("dependency_analysis", {})
                return cascade_analysis.get("critical_impacts", 0) > 0
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating system condition: {e}")
            return False
    
    async def _create_component_alert(self, rule: ComponentAlertRule, component: Dict[str, Any], system_state: Dict[str, Any]) -> Optional[ComponentAlert]:
        """Create a component-specific alert."""
        try:
            alert_id = f"{rule.name}_{component['name']}_{int(datetime.utcnow().timestamp())}"
            
            # Check if similar alert is already active
            for existing_alert in self._active_alerts.values():
                if (existing_alert.rule_name == rule.name and 
                    existing_alert.component_name == component["name"] and
                    not existing_alert.resolved_at):
                    return None  # Don't create duplicate alert
            
            # Create alert message
            message = self._create_alert_message(rule, component, system_state)
            
            alert = ComponentAlert(
                alert_id=alert_id,
                rule_name=rule.name,
                component_name=component["name"],
                severity=rule.severity,
                condition=rule.condition,
                message=message,
                triggered_at=datetime.utcnow(),
                metadata={
                    "component": component,
                    "rule_metadata": rule.metadata,
                    "system_state_snapshot": {
                        "timestamp": system_state["timestamp"].isoformat(),
                        "total_components": len(system_state["components"]),
                        "unhealthy_count": system_state.get("unhealthy_count", 0)
                    }
                }
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Error creating component alert: {e}")
            return None
    
    async def _create_system_alert(self, rule: ComponentAlertRule, system_state: Dict[str, Any]) -> Optional[ComponentAlert]:
        """Create a system-level alert."""
        try:
            alert_id = f"{rule.name}_system_{int(datetime.utcnow().timestamp())}"
            
            # Check if similar alert is already active
            for existing_alert in self._active_alerts.values():
                if (existing_alert.rule_name == rule.name and 
                    existing_alert.component_name == "system" and
                    not existing_alert.resolved_at):
                    return None  # Don't create duplicate alert
            
            message = self._create_system_alert_message(rule, system_state)
            
            alert = ComponentAlert(
                alert_id=alert_id,
                rule_name=rule.name,
                component_name="system",
                severity=rule.severity,
                condition=rule.condition,
                message=message,
                triggered_at=datetime.utcnow(),
                metadata={
                    "rule_metadata": rule.metadata,
                    "system_state": system_state
                }
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Error creating system alert: {e}")
            return None
    
    def _create_alert_message(self, rule: ComponentAlertRule, component: Dict[str, Any], system_state: Dict[str, Any]) -> str:
        """Create alert message for component alerts."""
        comp_name = component["name"].split(".")[-1]  # Short name
        
        if rule.name == "critical_component_unhealthy":
            return f"Critical component '{comp_name}' is unhealthy. Response time: {component['response_time_ms']:.1f}ms. Message: {component['message']}"
        
        elif rule.name.startswith("high_response_time"):
            threshold = rule.metadata.get("threshold_ms", 0)
            return f"Component '{comp_name}' has high response time: {component['response_time_ms']:.1f}ms (threshold: {threshold}ms)"
        
        elif "unhealthy" in rule.name:
            return f"Component '{comp_name}' ({component['type']}) is unhealthy. Message: {component['message']}"
        
        else:
            return f"Alert triggered for component '{comp_name}': {rule.description}"
    
    def _create_system_alert_message(self, rule: ComponentAlertRule, system_state: Dict[str, Any]) -> str:
        """Create alert message for system-level alerts."""
        if rule.name == "multiple_components_unhealthy":
            count = system_state.get("unhealthy_count", 0)
            return f"Multiple components are unhealthy: {count} components affected"
        
        elif rule.name == "system_degradation":
            percentage = system_state.get("degraded_percentage", 0) * 100
            return f"System degradation detected: {percentage:.1f}% of components are degraded"
        
        elif rule.name == "dependency_cascade_failure":
            cascade = system_state.get("dependency_analysis", {})
            critical_impacts = cascade.get("critical_impacts", 0)
            return f"Cascading failure detected: {critical_impacts} critical impacts identified"
        
        else:
            return f"System alert triggered: {rule.description}"
    
    async def _process_alert(self, alert: ComponentAlert) -> None:
        """Process a triggered alert."""
        try:
            # Add to active alerts
            self._active_alerts[alert.alert_id] = alert
            
            # Add to history
            self._alert_history.append(alert)
            
            # Limit history size
            if len(self._alert_history) > 1000:
                self._alert_history = self._alert_history[-800:]  # Keep last 800
            
            # Send notifications (would integrate with notification system)
            await self._send_alert_notification(alert)
            
            # Log alert
            logger.warning(f"Component alert triggered: {alert.rule_name} - {alert.message}")
            
            # Schedule escalation if needed
            rule = self._rules.get(alert.rule_name)
            if rule and rule.escalation_delay_minutes > 0:
                # Would schedule escalation task
                pass
            
        except Exception as e:
            logger.error(f"Error processing alert {alert.alert_id}: {e}")
    
    async def _send_alert_notification(self, alert: ComponentAlert) -> None:
        """Send alert notifications."""
        try:
            rule = self._rules.get(alert.rule_name)
            if not rule:
                return
            
            # Create notification payload
            notification = {
                "alert_id": alert.alert_id,
                "rule_name": alert.rule_name,
                "component": alert.component_name,
                "severity": alert.severity.value,
                "message": alert.message,
                "triggered_at": alert.triggered_at.isoformat(),
                "channels": rule.notification_channels
            }
            
            # Would send to notification system
            logger.debug(f"Alert notification: {notification}")
            
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")
    
    async def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        try:
            if alert_id in self._active_alerts:
                alert = self._active_alerts[alert_id]
                alert.acknowledged = True
                alert.metadata["acknowledged_by"] = user
                alert.metadata["acknowledged_at"] = datetime.utcnow().isoformat()
                
                logger.info(f"Alert {alert_id} acknowledged by {user}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str, user: Optional[str] = None, auto_resolved: bool = False) -> bool:
        """Resolve an alert."""
        try:
            if alert_id in self._active_alerts:
                alert = self._active_alerts[alert_id]
                alert.resolved_at = datetime.utcnow()
                alert.auto_resolved = auto_resolved
                
                if user:
                    alert.metadata["resolved_by"] = user
                
                logger.info(f"Alert {alert_id} resolved" + (f" by {user}" if user else " automatically"))
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error resolving alert {alert_id}: {e}")
            return False
    
    async def check_auto_resolution(self) -> int:
        """Check for alerts that should be auto-resolved."""
        resolved_count = 0
        
        try:
            system_state = await self._get_system_state()
            
            for alert_id, alert in list(self._active_alerts.items()):
                if alert.resolved_at:
                    continue
                
                rule = self._rules.get(alert.rule_name)
                if not rule or not rule.auto_resolve:
                    continue
                
                # Check if condition is no longer met
                should_resolve = False
                
                if alert.component_name == "system":
                    should_resolve = not await self._evaluate_system_condition(rule, system_state)
                else:
                    component = next((c for c in system_state["components"] if c["name"] == alert.component_name), None)
                    if component:
                        should_resolve = not await self._evaluate_component_condition(rule, component, system_state)
                
                if should_resolve:
                    await self.resolve_alert(alert_id, auto_resolved=True)
                    resolved_count += 1
            
            return resolved_count
            
        except Exception as e:
            logger.error(f"Error checking auto-resolution: {e}")
            return 0
    
    # Public API methods
    
    def get_active_alerts(self) -> List[ComponentAlert]:
        """Get all active (unresolved) alerts."""
        return [alert for alert in self._active_alerts.values() if not alert.resolved_at]
    
    def get_alert_history(self, limit: int = 100) -> List[ComponentAlert]:
        """Get alert history."""
        return self._alert_history[-limit:] if limit else self._alert_history
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        active_alerts = self.get_active_alerts()
        
        return {
            "active_alerts": len(active_alerts),
            "total_alerts_today": len([a for a in self._alert_history if (datetime.utcnow() - a.triggered_at).days == 0]),
            "alerts_by_severity": {
                severity.value: len([a for a in active_alerts if a.severity == severity])
                for severity in AlertSeverity
            },
            "alerts_by_component": {
                alert.component_name: len([a for a in active_alerts if a.component_name == alert.component_name])
                for alert in active_alerts
            },
            "most_frequent_rules": self._get_most_frequent_rules(),
            "avg_resolution_time_minutes": self._calculate_avg_resolution_time()
        }
    
    def _get_most_frequent_rules(self) -> List[Dict[str, Any]]:
        """Get most frequently triggered alert rules."""
        rule_counts = {}
        for alert in self._alert_history[-100:]:  # Last 100 alerts
            rule_counts[alert.rule_name] = rule_counts.get(alert.rule_name, 0) + 1
        
        return [
            {"rule_name": rule_name, "count": count}
            for rule_name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
    
    def _calculate_avg_resolution_time(self) -> float:
        """Calculate average resolution time for resolved alerts."""
        resolved_alerts = [a for a in self._alert_history if a.resolved_at]
        if not resolved_alerts:
            return 0.0
        
        resolution_times = [
            (alert.resolved_at - alert.triggered_at).total_seconds() / 60
            for alert in resolved_alerts[-50:]  # Last 50 resolved alerts
        ]
        
        return sum(resolution_times) / len(resolution_times)


# Alert evaluation functions for integration with existing alert engine

async def _evaluate_component_health_alerts(system_state: Dict[str, Any]) -> List[AnomalyDetectionResult]:
    """Evaluate component health alerts for the existing alert engine."""
    anomalies = []
    
    try:
        # Component health anomalies
        for component in system_state.get("components", []):
            if component["health_status"] == "unhealthy" and component["critical"]:
                anomalies.append(AnomalyDetectionResult(
                    component_name=component["name"],
                    anomaly_type=AnomalyType.THRESHOLD,
                    severity=AlertSeverity.CRITICAL,
                    confidence=0.95,
                    description=f"Critical component {component['name']} is unhealthy",
                    metadata={"component": component},
                    timestamp=datetime.utcnow()
                ))
    
    except Exception as e:
        logger.error(f"Error evaluating component health alerts: {e}")
    
    return anomalies


async def _evaluate_component_performance_alerts(system_state: Dict[str, Any]) -> List[AnomalyDetectionResult]:
    """Evaluate component performance alerts."""
    anomalies = []
    
    try:
        for component in system_state.get("components", []):
            if component["response_time_ms"] > 10000:  # 10 seconds
                anomalies.append(AnomalyDetectionResult(
                    component_name=component["name"],
                    anomaly_type=AnomalyType.PERFORMANCE,
                    severity=AlertSeverity.WARNING,
                    confidence=0.8,
                    description=f"Component {component['name']} has very high response time: {component['response_time_ms']}ms",
                    metadata={"component": component},
                    timestamp=datetime.utcnow()
                ))
    
    except Exception as e:
        logger.error(f"Error evaluating component performance alerts: {e}")
    
    return anomalies


async def _evaluate_dependency_alerts(system_state: Dict[str, Any]) -> List[AnomalyDetectionResult]:
    """Evaluate dependency-related alerts."""
    anomalies = []
    
    try:
        cascade_analysis = system_state.get("dependency_analysis", {})
        if cascade_analysis.get("critical_impacts", 0) > 0:
            anomalies.append(AnomalyDetectionResult(
                component_name="dependency_system",
                anomaly_type=AnomalyType.PATTERN,
                severity=AlertSeverity.CRITICAL,
                confidence=0.9,
                description=f"Cascading failure detected: {cascade_analysis['critical_impacts']} critical impacts",
                metadata={"cascade_analysis": cascade_analysis},
                timestamp=datetime.utcnow()
            ))
    
    except Exception as e:
        logger.error(f"Error evaluating dependency alerts: {e}")
    
    return anomalies


async def _evaluate_system_health_alerts(system_state: Dict[str, Any]) -> List[AnomalyDetectionResult]:
    """Evaluate system-wide health alerts."""
    anomalies = []
    
    try:
        # System degradation
        if system_state.get("degraded_percentage", 0) > 0.5:
            anomalies.append(AnomalyDetectionResult(
                component_name="system_health",
                anomaly_type=AnomalyType.THRESHOLD,
                severity=AlertSeverity.WARNING,
                confidence=0.8,
                description=f"System degradation: {system_state['degraded_percentage']:.1%} of components degraded",
                metadata={"system_state": system_state},
                timestamp=datetime.utcnow()
            ))
    
    except Exception as e:
        logger.error(f"Error evaluating system health alerts: {e}")
    
    return anomalies


# Global alert manager instance
_component_alert_manager: Optional[ComponentAlertManager] = None


def get_component_alert_manager() -> ComponentAlertManager:
    """Get the global component alert manager instance."""
    global _component_alert_manager
    if _component_alert_manager is None:
        _component_alert_manager = ComponentAlertManager()
    return _component_alert_manager


async def initialize_component_alert_manager() -> ComponentAlertManager:
    """Initialize the global component alert manager."""
    manager = get_component_alert_manager()
    await manager.initialize()
    return manager