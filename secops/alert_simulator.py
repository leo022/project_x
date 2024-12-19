import random
from datetime import datetime, timedelta
import ipaddress

class HIPSAlertSimulator:
    def __init__(self):
        self.attack_types = [
            "Buffer Overflow Attempt",
            "Suspicious Process Creation",
            "Unauthorized File Access",
            "Registry Modification",
            "Privilege Escalation",
            "Suspicious Script Execution",
            "Memory Injection",
            "DLL Hijacking Attempt"
        ]
        
        self.processes = [
            "svchost.exe", "explorer.exe", "cmd.exe",
            "powershell.exe", "rundll32.exe", "regsvr32.exe",
            "msiexec.exe", "winlogon.exe"
        ]
        
        self.severity_levels = ["Low", "Medium", "High", "Critical"]
        
    def generate_timestamp(self):
        now = datetime.now()
        random_minutes = random.randint(-60, 0)
        alert_time = now + timedelta(minutes=random_minutes)
        return alert_time.strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_ip(self):
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    
    def generate_alert(self):
        timestamp = self.generate_timestamp()
        attack_type = random.choice(self.attack_types)
        process = random.choice(self.processes)
        severity = random.choice(self.severity_levels)
        source_ip = self.generate_ip()
        pid = random.randint(1000, 65000)
        
        alert_templates = [
            f"[{timestamp}] HIPS Alert: {attack_type} detected from process {process} (PID: {pid}). Source IP: {source_ip}. Severity: {severity}",
            f"[{timestamp}] Security Warning: {process} (PID: {pid}) triggered {attack_type}. Origin: {source_ip}. Risk Level: {severity}",
            f"[{timestamp}] Threat Detected: {attack_type} involving {process}. Process ID: {pid}, Source: {source_ip}, Priority: {severity}"
        ]
        
        return random.choice(alert_templates)
    
    def generate_batch(self, num_alerts, include_similar=True):
        """
        Generate a batch of alerts, optionally including similar alerts
        
        Args:
            num_alerts (int): Number of alerts to generate
            include_similar (bool): If True, some alerts will be variations of the same event
        
        Returns:
            list: Generated alerts
        """
        alerts = []
        base_alerts = []
        
        for _ in range(num_alerts):
            if include_similar and base_alerts and random.random() < 0.3:
                # Generate a variation of an existing alert
                base_alert = random.choice(base_alerts)
                modified_alert = base_alert.replace(
                    self.generate_timestamp(),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ).replace(
                    self.generate_ip(),
                    str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
                )
                alerts.append(modified_alert)
            else:
                new_alert = self.generate_alert()
                alerts.append(new_alert)
                base_alerts.append(new_alert)
                
        return alerts 