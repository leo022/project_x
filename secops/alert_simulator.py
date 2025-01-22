import random
from datetime import datetime, timedelta
import ipaddress
from typing import Dict, List, Optional

class HIPSAlertSimulator:
    def __init__(self):
        # Cache alert templates for better performance
        self._alert_templates = [
            "[{timestamp}] HIPS Alert [{alert_type}]: {pattern} detected from process {process} "
            "(PID: {pid}). Source IP: {source_ip}. Severity: {severity}",
            
            "[{timestamp}] Security Warning [{alert_type}]: {process} (PID: {pid}) triggered {pattern}. "
            "Origin: {source_ip}. Risk Level: {severity}",
            
            "[{timestamp}] Threat Detected [{alert_type}]: {pattern} involving {process}. "
            "Process ID: {pid}, Source: {source_ip}, Priority: {severity}"
        ]
        
        # Pre-calculate alert types list for better performance
        self._alert_type_list = list(self._get_alert_types().keys())
        
        # Cache current time
        self._current_time = datetime.now()
        self._update_interval = timedelta(minutes=5)
        self._last_update = self._current_time

    @staticmethod
    def _get_alert_types() -> Dict:
        """Static configuration of alert types"""
        return {
            "ACCESS_VIOLATION": {
                "patterns": [
                    "Unauthorized File Access",
                    "Directory Traversal Attempt",
                    "Protected Resource Access",
                    "Restricted File Modification"
                ],
                "severity_range": ["Medium", "High"],
                "typical_processes": ["explorer.exe", "cmd.exe", "powershell.exe"]
            },
            "MEMORY_ATTACK": {
                "patterns": [
                    "Buffer Overflow Attempt",
                    "Memory Injection",
                    "Heap Spray Detected",
                    "Stack Manipulation"
                ],
                "severity_range": ["High", "Critical"],
                "typical_processes": ["svchost.exe", "rundll32.exe", "iexplore.exe"]
            },
            "PRIVILEGE_ESCALATION": {
                "patterns": [
                    "UAC Bypass Attempt",
                    "Privilege Elevation",
                    "Token Manipulation",
                    "SYSTEM Access Attempt"
                ],
                "severity_range": ["High", "Critical"],
                "typical_processes": ["cmd.exe", "powershell.exe", "winlogon.exe"]
            },
            "SUSPICIOUS_EXECUTION": {
                "patterns": [
                    "Suspicious Script Execution",
                    "Unusual Process Creation",
                    "Command Line Anomaly",
                    "Unsigned Binary Execution"
                ],
                "severity_range": ["Medium", "High"],
                "typical_processes": ["wscript.exe", "cscript.exe", "mshta.exe"]
            },
            "SYSTEM_TAMPERING": {
                "patterns": [
                    "Registry Modification",
                    "System File Tampering",
                    "Service Configuration Change",
                    "Boot Configuration Modification"
                ],
                "severity_range": ["Medium", "High", "Critical"],
                "typical_processes": ["regedit.exe", "msiexec.exe", "regsvr32.exe"]
            }
        }

    def _update_current_time(self) -> None:
        """Update current time if update interval has passed"""
        now = datetime.now()
        if now - self._last_update > self._update_interval:
            self._current_time = now
            self._last_update = now

    def generate_timestamp(self) -> str:
        """Generate a timestamp within the last hour"""
        self._update_current_time()
        random_minutes = random.randint(-60, 0)
        alert_time = self._current_time + timedelta(minutes=random_minutes)
        return alert_time.strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def generate_ip() -> str:
        """Generate a random IPv4 address"""
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    
    def generate_alert(self, specific_type: Optional[str] = None) -> Dict:
        """
        Generate a single alert with optional type specification
        
        Args:
            specific_type: Optional alert type to generate
        
        Returns:
            Dict containing alert information
        """
        alert_types = self._get_alert_types()
        timestamp = self.generate_timestamp()
        alert_type = specific_type if specific_type else random.choice(self._alert_type_list)
        alert_data = alert_types[alert_type]
        
        # Select components for the alert
        pattern = random.choice(alert_data["patterns"])
        severity = random.choice(alert_data["severity_range"])
        process = random.choice(alert_data["typical_processes"])
        source_ip = self.generate_ip()
        pid = random.randint(1000, 65000)
        
        # Format alert message using template
        raw_message = random.choice(self._alert_templates).format(
            timestamp=timestamp,
            alert_type=alert_type,
            pattern=pattern,
            process=process,
            pid=pid,
            source_ip=source_ip,
            severity=severity
        )
        
        return {
            "raw_message": raw_message,
            "type": alert_type,
            "pattern": pattern,
            "severity": severity,
            "process": process,
            "pid": pid,
            "source_ip": source_ip,
            "timestamp": timestamp
        }
    
    def generate_batch(self, num_alerts: int, include_similar: bool = True) -> List[Dict]:
        """
        Generate a batch of alerts, optionally including similar alerts
        
        Args:
            num_alerts: Number of alerts to generate
            include_similar: If True, some alerts will be variations of the same event
        
        Returns:
            List of generated alerts
        """
        alerts = []
        base_alerts = []
        
        for _ in range(num_alerts):
            if include_similar and base_alerts and random.random() < 0.3:
                # Generate a variation of an existing alert
                base_alert = random.choice(base_alerts)
                modified_alert = base_alert.copy()
                
                # Update dynamic fields
                modified_alert.update({
                    "timestamp": self.generate_timestamp(),
                    "source_ip": self.generate_ip(),
                    "pid": random.randint(1000, 65000)
                })
                
                # Update raw message efficiently
                modified_alert["raw_message"] = modified_alert["raw_message"].replace(
                    base_alert["timestamp"], modified_alert["timestamp"]
                ).replace(
                    base_alert["source_ip"], modified_alert["source_ip"]
                ).replace(
                    str(base_alert["pid"]), str(modified_alert["pid"])
                )
                
                alerts.append(modified_alert)
            else:
                new_alert = self.generate_alert()
                alerts.append(new_alert)
                base_alerts.append(new_alert)
                
        return alerts