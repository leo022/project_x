import random
from datetime import datetime, timedelta
import ipaddress

class HIPSAlertSimulator:
    def __init__(self):
        # Define alert categories and their specific patterns
        self.alert_types = {
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
        
    def generate_timestamp(self):
        now = datetime.now()
        random_minutes = random.randint(-60, 0)
        alert_time = now + timedelta(minutes=random_minutes)
        return alert_time.strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_ip(self):
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    
    def generate_alert(self, specific_type=None):
        """
        Generate a single alert with optional type specification
        
        Args:
            specific_type (str): Optional alert type to generate (must be one of self.alert_types keys)
        """
        timestamp = self.generate_timestamp()
        alert_type = specific_type if specific_type else random.choice(list(self.alert_types.keys()))
        alert_data = self.alert_types[alert_type]
        
        # Select components for the alert
        pattern = random.choice(alert_data["patterns"])
        severity = random.choice(alert_data["severity_range"])
        process = random.choice(alert_data["typical_processes"])
        source_ip = self.generate_ip()
        pid = random.randint(1000, 65000)
        
        alert_templates = [
            f"[{timestamp}] HIPS Alert [{alert_type}]: {pattern} detected from process {process} "
            f"(PID: {pid}). Source IP: {source_ip}. Severity: {severity}",
            
            f"[{timestamp}] Security Warning [{alert_type}]: {process} (PID: {pid}) triggered {pattern}. "
            f"Origin: {source_ip}. Risk Level: {severity}",
            
            f"[{timestamp}] Threat Detected [{alert_type}]: {pattern} involving {process}. "
            f"Process ID: {pid}, Source: {source_ip}, Priority: {severity}"
        ]
        
        return {
            "raw_message": random.choice(alert_templates),
            "type": alert_type,
            "pattern": pattern,
            "severity": severity,
            "process": process,
            "pid": pid,
            "source_ip": source_ip,
            "timestamp": timestamp
        }
    
    def generate_batch(self, num_alerts, include_similar=True):
        """
        Generate a batch of alerts, optionally including similar alerts
        
        Args:
            num_alerts (int): Number of alerts to generate
            include_similar (bool): If True, some alerts will be variations of the same event
        
        Returns:
            list: Generated alerts (list of dictionaries)
        """
        alerts = []
        base_alerts = []
        
        for _ in range(num_alerts):
            if include_similar and base_alerts and random.random() < 0.3:
                # Generate a variation of an existing alert
                base_alert = random.choice(base_alerts)
                modified_alert = base_alert.copy()
                modified_alert.update({
                    "timestamp": self.generate_timestamp(),
                    "source_ip": self.generate_ip(),
                    "pid": random.randint(1000, 65000)
                })
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