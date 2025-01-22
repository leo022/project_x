from secops.alert_simulator import HIPSAlertSimulator
from secops.syslog_vectorization import SyslogAlertAnalyzer
from datetime import datetime
import time
import argparse
from typing import Dict, Optional

class AlertMonitor:
    def __init__(self):
        self.simulator = HIPSAlertSimulator()
        self.analyzer = SyslogAlertAnalyzer()
        
        # Cache emoji mappings
        self._priority_emoji = {
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }
        
    def _get_priority(self, score: float) -> str:
        """Determine priority level based on score"""
        if score > 0.7:
            return "HIGH"
        elif score > 0.4:
            return "MEDIUM"
        return "LOW"

    def print_header(self) -> None:
        """Print application header"""
        print("\n" + "="*80)
        print("🛡️  HIPS ALERT ANALYSIS SYSTEM")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")

    def print_alert_details(self, alert: Dict, analysis: Dict) -> None:
        """Print detailed analysis of a single alert"""
        priority = self._get_priority(analysis['score'])
        
        print("\n" + "="*80)
        print(f"{self._priority_emoji[priority]} PRIORITY: {priority} | Type: {alert['type']}")
        print("-"*80)
        
        # Alert Information
        print("📝 Alert Details:")
        print(f"  • Pattern: {alert['pattern']}")
        print(f"  • Process: {alert['process']} (PID: {alert['pid']})")
        print(f"  • Severity: {alert['severity']}")
        print(f"  • Source IP: {alert['source_ip']}")
        print(f"  • Timestamp: {alert['timestamp']}")
        
        # Analysis Results
        print("\n📊 Risk Analysis:")
        print(f"  • Final Score: {analysis['score']:.3f}")
        print(f"  • Type Base Score: {analysis['type_score']:.3f}")
        print(f"  • Severity Weight: {analysis['severity_score']:.3f}")
        print(f"  • Uniqueness Score: {analysis['uniqueness']:.3f}")
        print(f"  • Type Frequency: #{analysis['type_frequency']}")
        if 'similarity' in analysis:
            print(f"  • Similarity to Previous: {analysis['similarity']:.3f}")
        print("="*80)

    def print_type_statistics(self, stats: Dict) -> None:
        """Print type-based analysis statistics"""
        print("\n" + "="*80)
        print("📊 ALERT TYPE ANALYSIS")
        print("-"*80)
        
        total_alerts = stats['total_alerts']
        
        # Print distribution by type
        print("\n🏷️  Alert Distribution by Type:")
        for type_stat in stats['type_distribution']:
            type_name = type_stat['alert_type']
            count = type_stat['total_alerts']
            unique = type_stat['unique_patterns']
            ratio = type_stat['repetition_ratio']
            
            percentage = (count / total_alerts) * 100
            bar = "█" * int(percentage/5)
            
            print(f"\n{type_name}:")
            print(f"  • Count: {count} ({percentage:.1f}%) {bar}")
            print(f"  • Unique Patterns: {unique}")
            print(f"  • Repetition Ratio: {ratio:.2f}")
        
        print("="*80)

    def explain_scoring_system(self) -> None:
        """Explain the label-based scoring system"""
        print("\n" + "="*80)
        print("🎯 LABEL-BASED SCORING SYSTEM")
        print("="*80)

        # Type Weights
        print("\n1️⃣  TYPE-SPECIFIC BASE WEIGHTS (30%)")
        print("-"*40)
        for alert_type, weight in self.analyzer.type_weights.items():
            print(f"  • {alert_type:<20} {weight:.2f}")

        # Severity Weights
        print("\n2️⃣  SEVERITY WEIGHTS (30%)")
        print("-"*40)
        for severity, weight in self.analyzer.severity_weights.items():
            print(f"  • {severity:<10} {weight:.2f}")

        # Uniqueness Scoring
        print("\n3️⃣  UNIQUENESS SCORING (40%)")
        print("-"*40)
        print("Based on type-specific pattern analysis:")
        print("  • Similarity Check: Within same alert type")
        print("  • Frequency Impact: Logarithmic decay per type")
        print("  • Uniqueness Formula: (similarity_factor + frequency_factor) / 2")
        
        print("\nExample Uniqueness Scores:")
        print("  • First occurrence:          1.000")
        print("  • Similar but different:     0.600")
        print("  • Repeated pattern:          0.300")
        print("  • Nearly identical:          0.150")
        
        print("\n📈 FINAL SCORE CALCULATION")
        print("-"*40)
        print("Score = (TypeWeight × 0.3) + (SeverityWeight × 0.3) + (Uniqueness × 0.4)")
        print("="*80)

    def simulate_realtime(self, interval: float = 2, duration: Optional[float] = None) -> None:
        """Simulate real-time alert monitoring"""
        start_time = time.time()
        alert_count = 0
        
        try:
            while True:
                if duration and (time.time() - start_time) > duration:
                    break
                    
                alert = self.simulator.generate_alert()
                analysis = self.analyzer.analyze_alert(alert)
                
                self.print_alert_details(alert, analysis)
                alert_count += 1
                
                # Print periodic statistics
                if alert_count % 5 == 0:
                    stats = self.analyzer.get_statistics()
                    self.print_type_statistics(stats)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped by user")
        finally:
            # Print final statistics
            stats = self.analyzer.get_statistics()
            self.print_type_statistics(stats)
            print(f"\nTotal monitoring time: {time.time() - start_time:.1f} seconds")
            print(f"Alerts processed: {alert_count}")

    def batch_analysis(self, num_alerts: int) -> None:
        """Perform batch analysis of alerts"""
        print(f"\nGenerating and analyzing {num_alerts} alerts...")
        alerts = self.simulator.generate_batch(num_alerts, include_similar=True)
        
        for alert in alerts:
            analysis = self.analyzer.analyze_alert(alert)
            self.print_alert_details(alert, analysis)
        
        stats = self.analyzer.get_statistics()
        self.print_type_statistics(stats)

def main():
    parser = argparse.ArgumentParser(description='HIPS Alert Analysis System')
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                      help='Analysis mode: batch or realtime')
    parser.add_argument('--count', type=int, default=15,
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