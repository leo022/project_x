from secops.alert_simulator import HIPSAlertSimulator
from secops.syslog_vectorization import SyslogAlertAnalyzer

def explain_scoring():
    """Explains the alert scoring system with examples"""
    print("\n� ALERT SCORING SYSTEM EXPLANATION 📊")
    print("="*80)
    print("\nThe alert scoring system combines two factors:")
    
    print("\n1. SIMILARITY FACTOR")
    print("-"*40)
    print("Measures how unique an alert is compared to previous alerts:")
    print("• Very unique (similarity < 0.3):   similarity_factor ≈ 0.7-1.0")
    print("• Somewhat unique (0.3-0.7):        similarity_factor ≈ 0.3-0.7")
    print("• Very similar (> 0.85):            similarity_factor = 0.0")
    
    print("\n2. FREQUENCY FACTOR")
    print("-"*40)
    print("Reduces score for repeatedly seen alerts:")
    print("• First occurrence:      factor = 0.500")
    print("• Second occurrence:     factor = 0.370")
    print("• Third occurrence:      factor = 0.310")
    print("• Fourth occurrence:     factor = 0.274")
    
    print("\n3. FINAL SCORE")
    print("-"*40)
    print("Average of similarity and frequency factors:")
    print("• 0.8 - 1.0: High priority   (unique, first-time alerts)")
    print("• 0.4 - 0.7: Medium priority (somewhat similar or repeated)")
    print("• 0.0 - 0.3: Low priority    (very similar or frequent)")
    print("="*80)

def print_alert_analysis(alert, analysis):
    """Pretty print the alert and its analysis"""
    print("\n" + "="*80)
    print(f"ALERT: {alert}")
    print("-"*80)
    print(f"Score: {analysis['score']:.3f}")
    print(f"Frequency: {analysis['frequency']}")
    if 'similarity' in analysis:
        print(f"Similarity to previous alerts: {analysis['similarity']:.3f}")
    print("="*80)

def main():
    # Initialize our components
    simulator = HIPSAlertSimulator()
    analyzer = SyslogAlertAnalyzer()
    
    print("\n🔒 HIPS Alert Analysis System 🔒\n")
    
    # Generate and analyze a batch of alerts
    num_alerts = 15
    print(f"Generating and analyzing {num_alerts} alerts...\n")
    alerts = simulator.generate_batch(num_alerts, include_similar=True)
    
    # Print simulated alerts
    # for alert in alerts:
    #     print(alert + "\n")

    # Process each alert
    for alert in alerts:
        analysis = analyzer.analyze_alert(alert)
        print_alert_analysis(alert, analysis)
    
    # Print summary statistics
    print("\n📊 SUMMARY STATISTICS 📊")
    print("-"*40)
    stats = analyzer.get_statistics()
    print(f"Total Alerts Processed: {stats['total_alerts']}")
    print(f"Unique Alert Patterns: {stats['unique_alerts']}")
    
    print("\nTop Frequent Alerts:")
    for idx, alert_info in enumerate(stats['top_frequent_alerts'], 1):
        print(f"\n{idx}. Frequency: {alert_info['frequency']}")
        print(f"   Alert: {alert_info['alert']}")
    
    # Explain the score
    explain_scoring()

if __name__ == "__main__":
    main() 