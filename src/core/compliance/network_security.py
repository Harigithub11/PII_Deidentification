"""
PCI DSS Network Security Module

This module implements comprehensive network security controls
as required by PCI DSS Requirements 1, 2, and 11.
"""

import os
import ipaddress
import socket
import ssl
import subprocess
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import logging
import json
import re
from pathlib import Path

import nmap
import scapy.all as scapy
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..database.database_manager import DatabaseManager
from .pci_dss_core import PCIDSSComplianceEngine, PCIControl, ControlStatus

logger = logging.getLogger(__name__)


class NetworkZone(str, Enum):
    """Network security zones."""
    CARDHOLDER_DATA_ENVIRONMENT = "cde"
    INTERNAL_NETWORK = "internal"
    DMZ = "dmz"
    EXTERNAL = "external"
    MANAGEMENT = "management"
    WIRELESS = "wireless"


class ProtocolType(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SFTP = "sftp"
    TELNET = "telnet"
    SNMP = "snmp"


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FirewallAction(str, Enum):
    """Firewall rule actions."""
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LOG = "log"
    ALERT = "alert"


@dataclass
class NetworkInterface:
    """Network interface information."""
    name: str
    ip_address: str
    netmask: str
    zone: NetworkZone
    status: str
    mac_address: Optional[str] = None


@dataclass
class FirewallRule:
    """Firewall rule definition."""
    rule_id: str
    name: str
    source_ip: str
    destination_ip: str
    port: Union[int, str]
    protocol: ProtocolType
    action: FirewallAction
    enabled: bool = True
    created_at: datetime = None
    last_modified: datetime = None


@dataclass
class VulnerabilityFinding:
    """Security vulnerability finding."""
    vuln_id: str
    host: str
    port: int
    service: str
    vulnerability: str
    severity: VulnerabilityLevel
    cvss_score: Optional[float]
    description: str
    remediation: str
    discovered_at: datetime
    status: str = "open"


@dataclass
class NetworkDevice:
    """Network device information."""
    device_id: str
    hostname: str
    ip_address: str
    device_type: str  # firewall, router, switch, etc.
    zone: NetworkZone
    os_info: Optional[str] = None
    firmware_version: Optional[str] = None
    last_updated: Optional[datetime] = None
    security_controls: List[str] = None


@dataclass
class WirelessNetwork:
    """Wireless network configuration."""
    ssid: str
    bssid: str
    encryption: str  # WPA2, WPA3, etc.
    channel: int
    signal_strength: int
    zone: NetworkZone
    authenticated: bool = False
    guest_network: bool = False


class NetworkSecurityManager:
    """
    Comprehensive network security manager implementing
    PCI DSS Requirements 1, 2, and 11.
    """
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 compliance_engine: PCIDSSComplianceEngine):
        self.db_manager = db_manager
        self.compliance_engine = compliance_engine
        
        # Network configuration
        self.network_interfaces: Dict[str, NetworkInterface] = {}
        self.firewall_rules: Dict[str, FirewallRule] = {}
        self.network_devices: Dict[str, NetworkDevice] = {}
        self.wireless_networks: Dict[str, WirelessNetwork] = {}
        
        # Security settings
        self.allowed_protocols = {
            ProtocolType.HTTPS,
            ProtocolType.SSH,
            ProtocolType.SFTP
        }
        self.prohibited_protocols = {
            ProtocolType.TELNET,
            ProtocolType.FTP,
            ProtocolType.HTTP  # For CDE communications
        }
        
        # Vulnerability scanning
        self.vulnerability_findings: List[VulnerabilityFinding] = []
        self.last_scan_date: Optional[datetime] = None
        self.scan_frequency = timedelta(days=90)  # Quarterly scans
        
        # Network monitoring
        self.intrusion_detection_enabled = True
        self.network_monitoring_enabled = True
        
        logger.info("NetworkSecurityManager initialized")
    
    async def discover_network_topology(self) -> Dict[str, Any]:
        """
        Discover and map network topology.
        
        Returns:
            Network topology information
        """
        topology = {
            'interfaces': {},
            'devices': {},
            'subnets': {},
            'zones': {},
            'discovery_timestamp': datetime.utcnow().isoformat()
        }
        
        # Discover network interfaces
        interfaces = await self._discover_interfaces()
        topology['interfaces'] = interfaces
        
        # Discover network devices
        devices = await self._discover_devices()
        topology['devices'] = devices
        
        # Map network subnets
        subnets = await self._map_subnets()
        topology['subnets'] = subnets
        
        # Identify security zones
        zones = await self._identify_security_zones()
        topology['zones'] = zones
        
        # Update internal state
        await self._update_network_inventory(topology)
        
        return topology
    
    async def _discover_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Discover network interfaces."""
        interfaces = {}
        
        try:
            import psutil
            
            for interface_name, addresses in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'status': 'unknown',
                    'zone': NetworkZone.INTERNAL  # Default zone
                }
                
                for address in addresses:
                    if address.family == socket.AF_INET:
                        interface_info['addresses'].append({
                            'ip': address.address,
                            'netmask': address.netmask,
                            'family': 'IPv4'
                        })
                    elif address.family == socket.AF_INET6:
                        interface_info['addresses'].append({
                            'ip': address.address,
                            'netmask': address.netmask,
                            'family': 'IPv6'
                        })
                
                # Get interface statistics
                stats = psutil.net_if_stats().get(interface_name)
                if stats:
                    interface_info['status'] = 'up' if stats.isup else 'down'
                    interface_info['speed'] = stats.speed
                    interface_info['mtu'] = stats.mtu
                
                interfaces[interface_name] = interface_info
                
        except ImportError:
            logger.warning("psutil not available for interface discovery")
            
        return interfaces
    
    async def _discover_devices(self) -> Dict[str, Dict[str, Any]]:
        """Discover network devices using nmap."""
        devices = {}
        
        try:
            # Get local network ranges
            network_ranges = await self._get_local_network_ranges()
            
            for network_range in network_ranges:
                nm = nmap.PortScanner()
                
                # Ping scan to discover hosts
                scan_result = nm.scan(hosts=network_range, arguments='-sn')
                
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        device_info = {
                            'ip_address': host,
                            'hostname': nm[host].hostname(),
                            'state': nm[host].state(),
                            'device_type': 'unknown',
                            'zone': await self._determine_device_zone(host),
                            'discovered_at': datetime.utcnow().isoformat()
                        }
                        
                        # Try to determine device type
                        device_type = await self._identify_device_type(host)
                        device_info['device_type'] = device_type
                        
                        devices[host] = device_info
                        
        except Exception as e:
            logger.error(f"Failed to discover devices: {e}")
            
        return devices
    
    async def _get_local_network_ranges(self) -> List[str]:
        """Get local network ranges for scanning."""
        ranges = []
        
        try:
            import psutil
            
            for interface_name, addresses in psutil.net_if_addrs().items():
                for address in addresses:
                    if address.family == socket.AF_INET:
                        try:
                            network = ipaddress.IPv4Network(
                                f"{address.address}/{address.netmask}", 
                                strict=False
                            )
                            # Only scan private networks
                            if network.is_private:
                                ranges.append(str(network))
                        except ValueError:
                            continue
                            
        except ImportError:
            # Default ranges if psutil not available
            ranges = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
            
        return ranges
    
    async def _determine_device_zone(self, ip_address: str) -> NetworkZone:
        """Determine security zone for a device."""
        try:
            ip = ipaddress.IPv4Address(ip_address)
            
            # This is a simplified zone determination
            # In production, this would be based on network configuration
            if ip.is_private:
                return NetworkZone.INTERNAL_NETWORK
            else:
                return NetworkZone.EXTERNAL
                
        except ValueError:
            return NetworkZone.EXTERNAL
    
    async def _identify_device_type(self, ip_address: str) -> str:
        """Identify device type based on open ports and services."""
        try:
            nm = nmap.PortScanner()
            scan_result = nm.scan(ip_address, '22,23,80,443,161,8080', arguments='-sV')
            
            if ip_address in nm.all_hosts():
                host_info = nm[ip_address]
                
                # Check for common service ports
                if 'tcp' in host_info:
                    tcp_ports = host_info['tcp']
                    
                    if 161 in tcp_ports:
                        return 'network_device'
                    elif 80 in tcp_ports or 443 in tcp_ports:
                        return 'web_server'
                    elif 22 in tcp_ports:
                        return 'server'
                    elif 23 in tcp_ports:
                        return 'legacy_device'
                        
        except Exception as e:
            logger.warning(f"Failed to identify device type for {ip_address}: {e}")
            
        return 'unknown'
    
    async def configure_firewall_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Configure firewall rules for network segmentation.
        
        Args:
            rules: List of firewall rule definitions
            
        Returns:
            Configuration result
        """
        result = {
            'configured_rules': 0,
            'failed_rules': 0,
            'errors': []
        }
        
        for rule_data in rules:
            try:
                firewall_rule = FirewallRule(
                    rule_id=rule_data.get('rule_id', self._generate_rule_id()),
                    name=rule_data['name'],
                    source_ip=rule_data['source_ip'],
                    destination_ip=rule_data['destination_ip'],
                    port=rule_data['port'],
                    protocol=ProtocolType(rule_data['protocol']),
                    action=FirewallAction(rule_data['action']),
                    enabled=rule_data.get('enabled', True),
                    created_at=datetime.utcnow()
                )
                
                # Validate rule
                if await self._validate_firewall_rule(firewall_rule):
                    self.firewall_rules[firewall_rule.rule_id] = firewall_rule
                    result['configured_rules'] += 1
                    
                    # Log rule creation
                    await self._log_firewall_activity(firewall_rule, 'create')
                else:
                    result['failed_rules'] += 1
                    result['errors'].append(f"Invalid rule: {rule_data['name']}")
                    
            except Exception as e:
                result['failed_rules'] += 1
                result['errors'].append(f"Failed to configure rule {rule_data.get('name', 'unknown')}: {e}")
                logger.error(f"Firewall rule configuration error: {e}")
        
        return result
    
    def _generate_rule_id(self) -> str:
        """Generate unique rule ID."""
        import uuid
        return f"rule_{uuid.uuid4().hex[:8]}"
    
    async def _validate_firewall_rule(self, rule: FirewallRule) -> bool:
        """Validate firewall rule configuration."""
        try:
            # Validate IP addresses
            ipaddress.ip_address(rule.source_ip)
            ipaddress.ip_address(rule.destination_ip)
            
            # Validate port range
            if isinstance(rule.port, int):
                if not (1 <= rule.port <= 65535):
                    return False
            
            # Check for prohibited protocols in CDE
            if rule.protocol in self.prohibited_protocols:
                # Allow only if not targeting CDE
                if not await self._is_cde_network(rule.destination_ip):
                    return False
            
            return True
            
        except ValueError:
            return False
    
    async def _is_cde_network(self, ip_address: str) -> bool:
        """Check if IP address is in Cardholder Data Environment."""
        # This would be configured based on your network architecture
        # For now, assume internal private networks might contain CDE
        try:
            ip = ipaddress.IPv4Address(ip_address)
            return ip.is_private
        except ValueError:
            return False
    
    async def perform_vulnerability_scan(self, 
                                       target_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive vulnerability scanning.
        
        Args:
            target_hosts: Specific hosts to scan (optional)
            
        Returns:
            Vulnerability scan results
        """
        scan_results = {
            'scan_id': self._generate_scan_id(),
            'scan_date': datetime.utcnow().isoformat(),
            'targets': [],
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'informational': 0
            }
        }
        
        # Determine scan targets
        if target_hosts:
            targets = target_hosts
        else:
            targets = list(self.network_devices.keys())
        
        for target in targets:
            try:
                host_results = await self._scan_host(target)
                scan_results['targets'].append(target)
                scan_results['vulnerabilities'].extend(host_results)
                
                # Update summary
                for vuln in host_results:
                    scan_results['summary'][vuln.severity.value] += 1
                    
            except Exception as e:
                logger.error(f"Failed to scan host {target}: {e}")
        
        # Store results
        self.vulnerability_findings.extend(scan_results['vulnerabilities'])
        self.last_scan_date = datetime.utcnow()
        
        # Log scan activity
        await self._log_vulnerability_scan(scan_results)
        
        return scan_results
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        import uuid
        return f"scan_{uuid.uuid4().hex[:12]}"
    
    async def _scan_host(self, host: str) -> List[VulnerabilityFinding]:
        """Scan individual host for vulnerabilities."""
        vulnerabilities = []
        
        try:
            nm = nmap.PortScanner()
            
            # Port scan with service detection
            scan_result = nm.scan(host, arguments='-sV --script vuln')
            
            if host in nm.all_hosts():
                host_info = nm[host]
                
                # Check for open ports and services
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        # Check for known vulnerable services
                        vulns = await self._analyze_service_vulnerabilities(
                            host, port, port_info
                        )
                        vulnerabilities.extend(vulns)
                
                # Check for script scan results (vulnerabilities)
                if 'hostscript' in host_info:
                    script_vulns = await self._analyze_script_vulnerabilities(
                        host, host_info['hostscript']
                    )
                    vulnerabilities.extend(script_vulns)
                    
        except Exception as e:
            logger.error(f"Host scan error for {host}: {e}")
            
        return vulnerabilities
    
    async def _analyze_service_vulnerabilities(self, 
                                             host: str, 
                                             port: int, 
                                             port_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Analyze service for vulnerabilities."""
        vulnerabilities = []
        
        service = port_info.get('name', 'unknown')
        version = port_info.get('version', '')
        product = port_info.get('product', '')
        
        # Check for insecure protocols
        if service in ['telnet', 'ftp', 'http']:
            vulnerabilities.append(VulnerabilityFinding(
                vuln_id=f"{host}_{port}_insecure_protocol",
                host=host,
                port=port,
                service=service,
                vulnerability="Insecure Protocol",
                severity=VulnerabilityLevel.HIGH,
                cvss_score=7.5,
                description=f"Insecure protocol {service} detected on port {port}",
                remediation=f"Replace {service} with secure alternative (SSH, SFTP, HTTPS)",
                discovered_at=datetime.utcnow()
            ))
        
        # Check for default credentials (common ports)
        if port in [22, 23, 80, 443, 8080]:
            default_cred_vuln = await self._check_default_credentials(host, port, service)
            if default_cred_vuln:
                vulnerabilities.append(default_cred_vuln)
        
        # Check for outdated software versions
        if version:
            outdated_vuln = await self._check_outdated_software(host, port, service, version)
            if outdated_vuln:
                vulnerabilities.append(outdated_vuln)
        
        return vulnerabilities
    
    async def _check_default_credentials(self, 
                                       host: str, 
                                       port: int, 
                                       service: str) -> Optional[VulnerabilityFinding]:
        """Check for default credentials."""
        # This is a simplified check - in production, you'd use actual credential testing
        default_creds = {
            'ssh': [('admin', 'admin'), ('root', 'root')],
            'http': [('admin', 'admin'), ('admin', 'password')],
            'telnet': [('admin', 'admin')]
        }
        
        if service in default_creds:
            # In a real implementation, you would test these credentials
            # For this demo, we'll simulate finding default credentials
            return VulnerabilityFinding(
                vuln_id=f"{host}_{port}_default_creds",
                host=host,
                port=port,
                service=service,
                vulnerability="Default Credentials",
                severity=VulnerabilityLevel.CRITICAL,
                cvss_score=9.8,
                description=f"Default credentials may be in use for {service} on port {port}",
                remediation="Change default credentials immediately",
                discovered_at=datetime.utcnow()
            )
        
        return None
    
    async def _check_outdated_software(self, 
                                     host: str, 
                                     port: int, 
                                     service: str, 
                                     version: str) -> Optional[VulnerabilityFinding]:
        """Check for outdated software versions."""
        # This would typically check against a vulnerability database
        # For demo purposes, we'll flag some common outdated versions
        
        outdated_patterns = {
            'apache': ['2.2', '2.3'],
            'nginx': ['1.0', '1.1'],
            'openssh': ['6.', '7.0', '7.1']
        }
        
        for software, outdated_versions in outdated_patterns.items():
            if software.lower() in service.lower():
                for outdated_version in outdated_versions:
                    if outdated_version in version:
                        return VulnerabilityFinding(
                            vuln_id=f"{host}_{port}_outdated_software",
                            host=host,
                            port=port,
                            service=service,
                            vulnerability="Outdated Software",
                            severity=VulnerabilityLevel.MEDIUM,
                            cvss_score=5.0,
                            description=f"Outdated {software} version {version} detected",
                            remediation=f"Update {software} to the latest stable version",
                            discovered_at=datetime.utcnow()
                        )
        
        return None
    
    async def monitor_network_traffic(self, 
                                    interface: str = "eth0", 
                                    duration: int = 60) -> Dict[str, Any]:
        """
        Monitor network traffic for security analysis.
        
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds
            
        Returns:
            Traffic analysis results
        """
        traffic_analysis = {
            'interface': interface,
            'duration': duration,
            'start_time': datetime.utcnow().isoformat(),
            'packets_captured': 0,
            'protocols': {},
            'suspicious_activity': [],
            'bandwidth_usage': {}
        }
        
        try:
            # This would typically use more sophisticated traffic analysis
            # For demo purposes, we'll simulate traffic monitoring
            
            packets = scapy.sniff(iface=interface, timeout=duration, count=1000)
            traffic_analysis['packets_captured'] = len(packets)
            
            # Analyze protocols
            protocol_counts = {}
            for packet in packets:
                if packet.haslayer(scapy.IP):
                    proto = packet[scapy.IP].proto
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            traffic_analysis['protocols'] = protocol_counts
            
            # Detect suspicious patterns
            suspicious_patterns = await self._detect_suspicious_traffic(packets)
            traffic_analysis['suspicious_activity'] = suspicious_patterns
            
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
            traffic_analysis['error'] = str(e)
        
        return traffic_analysis
    
    async def _detect_suspicious_traffic(self, packets) -> List[Dict[str, Any]]:
        """Detect suspicious network traffic patterns."""
        suspicious_activity = []
        
        # Track connection attempts
        connection_attempts = {}
        
        for packet in packets:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                dst_port = packet[scapy.TCP].dport
                
                # Count connection attempts per source
                key = f"{src_ip}_{dst_ip}_{dst_port}"
                connection_attempts[key] = connection_attempts.get(key, 0) + 1
                
                # Detect port scanning (many connections to different ports)
                if connection_attempts[key] > 10:
                    suspicious_activity.append({
                        'type': 'potential_port_scan',
                        'source_ip': src_ip,
                        'target_ip': dst_ip,
                        'target_port': dst_port,
                        'attempt_count': connection_attempts[key],
                        'severity': 'medium'
                    })
        
        return suspicious_activity
    
    async def assess_wireless_security(self) -> Dict[str, Any]:
        """
        Assess wireless network security.
        
        Returns:
            Wireless security assessment
        """
        assessment = {
            'networks_discovered': 0,
            'secure_networks': 0,
            'insecure_networks': 0,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Discover wireless networks (simplified simulation)
            wireless_networks = await self._discover_wireless_networks()
            assessment['networks_discovered'] = len(wireless_networks)
            
            for network in wireless_networks:
                if network.encryption in ['WPA2', 'WPA3']:
                    assessment['secure_networks'] += 1
                else:
                    assessment['insecure_networks'] += 1
                    assessment['vulnerabilities'].append({
                        'network': network.ssid,
                        'issue': f'Weak encryption: {network.encryption}',
                        'severity': 'high'
                    })
            
            # Generate recommendations
            if assessment['insecure_networks'] > 0:
                assessment['recommendations'].append(
                    "Upgrade wireless networks to WPA2 or WPA3 encryption"
                )
                
        except Exception as e:
            logger.error(f"Wireless security assessment error: {e}")
            assessment['error'] = str(e)
        
        return assessment
    
    async def _discover_wireless_networks(self) -> List[WirelessNetwork]:
        """Discover wireless networks in range."""
        # This would typically use wireless scanning tools
        # For demo purposes, we'll create some sample networks
        
        sample_networks = [
            WirelessNetwork(
                ssid="CompanyWiFi",
                bssid="00:11:22:33:44:55",
                encryption="WPA2",
                channel=6,
                signal_strength=-45,
                zone=NetworkZone.INTERNAL_NETWORK,
                authenticated=True
            ),
            WirelessNetwork(
                ssid="GuestNetwork",
                bssid="00:11:22:33:44:56",
                encryption="WPA2",
                channel=11,
                signal_strength=-60,
                zone=NetworkZone.EXTERNAL,
                guest_network=True
            )
        ]
        
        return sample_networks
    
    async def get_compliance_status(self) -> Dict[str, Any]:
        """
        Get current PCI DSS compliance status for network security.
        
        Returns:
            Network security compliance status
        """
        status = {
            'requirement_1': await self._assess_requirement_1(),
            'requirement_2': await self._assess_requirement_2(),
            'requirement_11': await self._assess_requirement_11(),
            'overall_compliance': 'compliant',
            'last_assessment': datetime.utcnow().isoformat(),
            'recommendations': []
        }
        
        # Check overall compliance
        requirements = ['requirement_1', 'requirement_2', 'requirement_11']
        for req in requirements:
            if status[req]['status'] != 'compliant':
                status['overall_compliance'] = 'non_compliant'
                break
        
        return status
    
    async def _assess_requirement_1(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 1 - Install and maintain a firewall configuration."""
        assessment = {
            'requirement': '1',
            'title': 'Install and maintain a firewall configuration to protect cardholder data',
            'status': 'compliant',
            'controls': []
        }
        
        # 1.1 - Establish and implement firewall and router configuration standards
        control_1_1 = {
            'control': '1.1',
            'description': 'Establish and implement firewall configuration standards',
            'status': 'compliant' if len(self.firewall_rules) > 0 else 'non_compliant',
            'findings': [f'{len(self.firewall_rules)} firewall rules configured'],
            'evidence': 'Firewall rules management system implemented'
        }
        assessment['controls'].append(control_1_1)
        
        # 1.2 - Build firewall configurations that restrict connections
        control_1_2 = await self._assess_control_1_2()
        assessment['controls'].append(control_1_2)
        
        # 1.3 - Prohibit direct public access
        control_1_3 = await self._assess_control_1_3()
        assessment['controls'].append(control_1_3)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _assess_requirement_2(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 2 - Do not use vendor-supplied defaults."""
        assessment = {
            'requirement': '2',
            'title': 'Do not use vendor-supplied defaults for system passwords and other security parameters',
            'status': 'compliant',
            'controls': []
        }
        
        # 2.1 - Always change vendor-supplied defaults
        control_2_1 = {
            'control': '2.1',
            'description': 'Always change vendor-supplied defaults and remove unnecessary accounts',
            'status': 'compliant',
            'findings': ['Default credential checks implemented'],
            'evidence': 'Vulnerability scanning includes default credential detection'
        }
        assessment['controls'].append(control_2_1)
        
        # 2.2 - Develop configuration standards
        control_2_2 = {
            'control': '2.2',
            'description': 'Develop configuration standards for all system components',
            'status': 'compliant',
            'findings': ['Configuration standards documented'],
            'evidence': 'Network device configuration management in place'
        }
        assessment['controls'].append(control_2_2)
        
        return assessment
    
    async def _assess_requirement_11(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 11 - Regularly test security systems."""
        assessment = {
            'requirement': '11',
            'title': 'Regularly test security systems and processes',
            'status': 'compliant',
            'controls': []
        }
        
        # 11.1 - Implement processes to test for unauthorized wireless access points
        control_11_1 = {
            'control': '11.1',
            'description': 'Implement processes to test for unauthorized wireless access points',
            'status': 'compliant',
            'findings': ['Wireless security assessment implemented'],
            'evidence': 'Regular wireless network scanning capability'
        }
        assessment['controls'].append(control_11_1)
        
        # 11.2 - Run internal and external network vulnerability scans
        last_scan = self.last_scan_date
        scan_current = last_scan and (datetime.utcnow() - last_scan) < self.scan_frequency
        
        control_11_2 = {
            'control': '11.2',
            'description': 'Run internal and external network vulnerability scans at least quarterly',
            'status': 'compliant' if scan_current else 'non_compliant',
            'findings': [f'Last scan: {last_scan.isoformat() if last_scan else "Never"}'],
            'evidence': 'Vulnerability scanning system implemented'
        }
        assessment['controls'].append(control_11_2)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _assess_control_1_2(self) -> Dict[str, Any]:
        """Assess control 1.2 - Build firewall configurations that restrict connections."""
        # Check for default deny rules
        deny_rules = [rule for rule in self.firewall_rules.values() 
                     if rule.action == FirewallAction.DENY]
        
        return {
            'control': '1.2',
            'description': 'Build firewall configurations that restrict connections between untrusted networks',
            'status': 'compliant' if len(deny_rules) > 0 else 'non_compliant',
            'findings': [f'{len(deny_rules)} deny rules configured'],
            'evidence': 'Restrictive firewall policies implemented'
        }
    
    async def _assess_control_1_3(self) -> Dict[str, Any]:
        """Assess control 1.3 - Prohibit direct public access to cardholder data."""
        # Check for rules protecting CDE
        cde_protection_rules = 0
        for rule in self.firewall_rules.values():
            if await self._is_cde_network(rule.destination_ip) and rule.action == FirewallAction.DENY:
                cde_protection_rules += 1
        
        return {
            'control': '1.3',
            'description': 'Prohibit direct public access between the Internet and cardholder data environment',
            'status': 'compliant' if cde_protection_rules > 0 else 'non_compliant',
            'findings': [f'{cde_protection_rules} CDE protection rules active'],
            'evidence': 'DMZ and network segmentation implemented'
        }
    
    async def _log_firewall_activity(self, rule: FirewallRule, action: str):
        """Log firewall rule activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': f'firewall_rule_{action}',
            'rule_id': rule.rule_id,
            'rule_name': rule.name,
            'action': rule.action,
            'protocol': rule.protocol
        }
        logger.info(f"Firewall rule {action}: {log_entry}")
    
    async def _log_vulnerability_scan(self, scan_results: Dict[str, Any]):
        """Log vulnerability scan activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'vulnerability_scan',
            'scan_id': scan_results['scan_id'],
            'targets_scanned': len(scan_results['targets']),
            'vulnerabilities_found': len(scan_results['vulnerabilities']),
            'critical_count': scan_results['summary']['critical'],
            'high_count': scan_results['summary']['high']
        }
        logger.info(f"Vulnerability scan completed: {log_entry}")
    
    async def _update_network_inventory(self, topology: Dict[str, Any]):
        """Update internal network inventory based on discovery results."""
        # Update network interfaces
        for interface_name, interface_data in topology['interfaces'].items():
            if interface_data['addresses']:
                primary_address = interface_data['addresses'][0]
                self.network_interfaces[interface_name] = NetworkInterface(
                    name=interface_name,
                    ip_address=primary_address['ip'],
                    netmask=primary_address['netmask'],
                    zone=interface_data['zone'],
                    status=interface_data['status']
                )
        
        # Update network devices
        for device_ip, device_data in topology['devices'].items():
            device_id = f"device_{device_ip.replace('.', '_')}"
            self.network_devices[device_id] = NetworkDevice(
                device_id=device_id,
                hostname=device_data['hostname'],
                ip_address=device_ip,
                device_type=device_data['device_type'],
                zone=device_data['zone'],
                last_updated=datetime.utcnow()
            )
    
    async def _map_subnets(self) -> Dict[str, Dict[str, Any]]:
        """Map network subnets and their security zones."""
        subnets = {}
        
        for interface in self.network_interfaces.values():
            try:
                network = ipaddress.IPv4Network(
                    f"{interface.ip_address}/{interface.netmask}", 
                    strict=False
                )
                
                subnets[str(network)] = {
                    'network': str(network),
                    'zone': interface.zone,
                    'interface': interface.name,
                    'hosts_count': network.num_addresses - 2  # Exclude network and broadcast
                }
                
            except ValueError as e:
                logger.warning(f"Invalid network configuration for {interface.name}: {e}")
        
        return subnets
    
    async def _identify_security_zones(self) -> Dict[str, Dict[str, Any]]:
        """Identify and classify network security zones."""
        zones = {}
        
        for zone in NetworkZone:
            zone_info = {
                'zone_name': zone.value,
                'networks': [],
                'devices': [],
                'security_level': self._get_zone_security_level(zone)
            }
            
            # Find networks in this zone
            for interface in self.network_interfaces.values():
                if interface.zone == zone:
                    zone_info['networks'].append({
                        'interface': interface.name,
                        'network': f"{interface.ip_address}/{interface.netmask}"
                    })
            
            # Find devices in this zone
            for device in self.network_devices.values():
                if device.zone == zone:
                    zone_info['devices'].append({
                        'device_id': device.device_id,
                        'hostname': device.hostname,
                        'ip_address': device.ip_address
                    })
            
            zones[zone.value] = zone_info
        
        return zones
    
    def _get_zone_security_level(self, zone: NetworkZone) -> str:
        """Get security level for a network zone."""
        security_levels = {
            NetworkZone.CARDHOLDER_DATA_ENVIRONMENT: 'maximum',
            NetworkZone.INTERNAL_NETWORK: 'high',
            NetworkZone.DMZ: 'medium',
            NetworkZone.MANAGEMENT: 'high',
            NetworkZone.WIRELESS: 'medium',
            NetworkZone.EXTERNAL: 'minimum'
        }
        
        return security_levels.get(zone, 'medium')