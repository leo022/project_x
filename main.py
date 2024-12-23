from secops.alert_simulator import HIPSAlertSimulator
from secops.syslog_vectorization import SyslogAlertAnalyzer
from datetime import datetime
import time
import argparse
import sys

class AlertMonitor:
    def __init__(self):
        self.simulator = HIPSAlertSimulator()
        self.analyzer = SyslogAlertAnalyzer()
        
    def print_header(self):
        """Print application header"""
        print("\n" + "="*80)
        print(f"🛡️  HIPS ALERT ANALYSIS SYSTEM")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")

    def print_alert_details(self, alert, analysis):
        """Print detailed analysis of a single alert"""
        priority_emoji = {
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }
        
        # Determine priority level
        if analysis['score'] > 0.7:
            priority = "HIGH"
        elif analysis['score'] > 0.4:
            priority = "MEDIUM"
        else:
            priority = "LOW"
            
        print("\n" + "="*80)
        print(f"{priority_emoji[priority]} PRIORITY: {priority}")
        print("-"*80)
        
        # Alert Information
        print("📝 Alert Details:")
        print(f"  • Type: {alert['type']}")
        print(f"  • Pattern: {alert['pattern']}")
        print(f"  • Process: {alert['process']} (PID: {alert['pid']})")
        print(f"  • Severity: {alert['severity']}")
        print(f"  • Source IP: {alert['source_ip']}")
        print(f"  • Timestamp: {alert['timestamp']}")
        
        # Analysis Results
        print("\n📊 Risk Analysis:")
        print(f"  • Final Score: {analysis['score']:.3f}")
        print(f"  • Type Risk: {analysis['type_score']:.3f}")
        print(f"  • Severity Weight: {analysis['severity_score']:.3f}")
        print(f"  • Occurrence: #{analysis['frequency']}")
        print(f"  • Type Frequency: #{analysis['type_frequency']}")
        if 'similarity' in analysis:
            print(f"  • Similarity: {analysis['similarity']:.3f}")
        print("="*80)

    def print_statistics(self, stats):
        """Print analysis summary statistics"""
        print("\n" + "="*80)
        print("📈 ANALYSIS SUMMARY")
        print("-"*80)
        
        # Basic Stats
        print(f"Total Alerts: {stats['total_alerts']}")
        print(f"Unique Patterns: {stats['unique_alerts']}")
        
        # Type Distribution
        print("\n🔍 Alert Type Distribution:")
        for type_stat in stats['type_distribution']:
            percentage = (type_stat['frequency'] / stats['total_alerts']) * 100
            bar = "█" * int(percentage/5)  # Visual bar
            print(f"  {type_stat['alert_type']:<20} {type_stat['frequency']:>3} ({percentage:>5.1f}%) {bar}")
        
        # Severity Distribution
        print("\n⚠️ Severity Distribution:")
        for severity, count in stats['severity_distribution'].items():
            percentage = (count / stats['total_alerts']) * 100
            bar = "█" * int(percentage/5)
            print(f"  {severity:<10} {count:>3} ({percentage:>5.1f}%) {bar}")
        
        print("="*80)

    def simulate_realtime(self, interval=2, duration=None):
        """Simulate real-time alert monitoring"""
        start_time = time.time()
        alert_count = 0
        
        try:
            while True:
                # Check if duration limit reached
                if duration and (time.time() - start_time) > duration:
                    break
                
                # Generate and analyze new alert
                alert = self.simulator.generate_alert()
                analysis = self.analyzer.analyze_alert(alert)
                
                # Print analysis
                self.print_alert_details(alert, analysis)
                alert_count += 1
                
                # Print periodic statistics
                if alert_count % 5 == 0:
                    stats = self.analyzer.get_statistics()
                    self.print_statistics(stats)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped by user")
        finally:
            # Print final statistics
            stats = self.analyzer.get_statistics()
            self.print_statistics(stats)
            print(f"\nTotal monitoring time: {time.time() - start_time:.1f} seconds")
            print(f"Alerts processed: {alert_count}")

    def batch_analysis(self, num_alerts):
        """Perform batch analysis of alerts"""
        print(f"\nGenerating and analyzing {num_alerts} alerts...")
        alerts = self.simulator.generate_batch(num_alerts, include_similar=True)
        
        for alert in alerts:
            analysis = self.analyzer.analyze_alert(alert)
            self.print_alert_details(alert, analysis)
        
        stats = self.analyzer.get_statistics()
        self.print_statistics(stats)

    def explain_scoring_system(self):
        """Explain the alert scoring system and risk analysis"""
        print("\n" + "="*80)
        print("🎯 ALERT SCORING SYSTEM EXPLANATION")
        print("="*80)

        # Component 1: Type-based Scoring
        print("\n1️⃣ TYPE-BASED SCORING (30% of final score)")
        print("-"*40)
        print("Different attack types have different base risk weights:")
        type_weights = {
            "MEMORY_ATTACK": "0.90 - Highest risk due to potential system compromise",
            "PRIVILEGE_ESCALATION": "0.85 - Critical due to elevated access attempts",
            "SYSTEM_TAMPERING": "0.75 - High risk system modifications",
            "ACCESS_VIOLATION": "0.70 - Unauthorized access attempts",
            "SUSPICIOUS_EXECUTION": "0.65 - Potentially malicious activity"
        }
        for type_name, description in type_weights.items():
            print(f"  • {type_name:<20} | {description}")

        # Component 2: Severity-based Scoring
        print("\n2️⃣ SEVERITY-BASED SCORING (30% of final score)")
        print("-"*40)
        severity_weights = {
            "Critical": "1.00 - Immediate action required",
            "High": "0.80 - Urgent attention needed",
            "Medium": "0.60 - Moderate risk level",
            "Low": "0.30 - Minimal immediate risk"
        }
        for severity, description in severity_weights.items():
            print(f"  • {severity:<10} | {description}")

        # Component 3: Similarity Analysis
        print("\n3️⃣ SIMILARITY ANALYSIS (20% of final score)")
        print("-"*40)
        print("Measures how unique an alert is compared to previous alerts:")
        print("  • Unique alerts (similarity < 0.30)     → Higher score")
        print("  • Similar alerts (0.30 < sim < 0.85)    → Reduced score")
        print("  • Nearly identical (similarity > 0.85)   → Minimal score")
        print("\nFormula: similarity_factor = 1 - similarity_score")

        # Component 4: Frequency Analysis
        print("\n4️⃣ FREQUENCY ANALYSIS (20% of final score)")
        print("-"*40)
        print("Reduces score for repeatedly seen alerts:")
        print("Formula: frequency_factor = 1 / (1 + log(1 + occurrence_count))")
        print("\nExample frequency penalties:")
        frequencies = [(1, 1.000), (2, 0.630), (5, 0.386), (10, 0.292)]
        for count, score in frequencies:
            print(f"  • Occurrence #{count:<2} → Score factor: {score:.3f}")

        # Final Score Calculation
        print("\n🎯 FINAL SCORE CALCULATION")
        print("-"*40)
        print("Final score = 0.30 * type_score + 0.30 * severity_score + 0.20 * similarity_factor + 0.20 * frequency_factor")
        print("="*80)

def main():
    parser = argparse.ArgumentParser(description='HIPS Alert Analysis System')
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                      help='Analysis mode: batch or realtime')
    parser.add_argument('--count', type=int, default=10,
                      help='Number of alerts to generate in batch mode')
    parser.add_argument('--interval', type=float, default=2,
                      help='Interval between alerts in realtime mode (seconds)')
    parser.add_argument('--duration', type=int,
                      help='Duration to run in realtime mode (seconds)')
    
    args = parser.parse_args()
    
    monitor = AlertMonitor()
    monitor.print_header()
    
    if args.mode == 'realtime':
        monitor.simulate_realtime(args.interval, args.duration)
    else:
        monitor.batch_analysis(args.count)

if __name__ == "__main__":
    main() 