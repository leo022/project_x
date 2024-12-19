import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
import re
import pandas as pd
from secops.alert_simulator import HIPSAlertSimulator

class SyslogAlertAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            token_pattern=r'\b\w+\b',
            ngram_range=(1, 2)
        )
        self.alert_vectors = None
        self.alert_history = []
        self.similarity_threshold = 0.85
        self.alert_counts = defaultdict(int)
    
    def preprocess_alert(self, alert):
        # Remove timestamps and IP addresses
        alert = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDR', alert)
        alert = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', 'TIMESTAMP', alert)
        return alert.lower()
    
    def vectorize_alerts(self, alerts):
        processed_alerts = [self.preprocess_alert(alert) for alert in alerts]
        return self.vectorizer.fit_transform(processed_alerts)
    
    def calculate_similarity_score(self, new_alert):
        new_vector = self.vectorizer.transform([self.preprocess_alert(new_alert)])
        similarities = cosine_similarity(new_vector, self.alert_vectors)
        return np.max(similarities)
    
    def analyze_alert(self, alert):
        if not self.alert_history:
            self.alert_history.append(alert)
            self.alert_vectors = self.vectorize_alerts(self.alert_history)
            self.alert_counts[alert] += 1
            return {'score': 1.0, 'frequency': 1}
        
        similarity_score = self.calculate_similarity_score(alert)
        self.alert_history.append(alert)
        self.alert_vectors = self.vectorize_alerts(self.alert_history)
        
        # Update frequency counter
        self.alert_counts[alert] += 1
        
        # Calculate normalized score (lower for similar/frequent alerts)
        frequency_factor = 1 / (1 + np.log1p(self.alert_counts[alert]))
        similarity_factor = 1 - similarity_score if similarity_score < self.similarity_threshold else 0
        final_score = (frequency_factor + similarity_factor) / 2
        
        return {
            'score': final_score,
            'frequency': self.alert_counts[alert],
            'similarity': similarity_score
        }
    
    def get_statistics(self):
        df = pd.DataFrame({
            'alert': list(self.alert_counts.keys()),
            'frequency': list(self.alert_counts.values())
        })
        return {
            'total_alerts': len(self.alert_history),
            'unique_alerts': len(self.alert_counts),
            'top_frequent_alerts': df.nlargest(5, 'frequency').to_dict('records')
        }

# Usage example
simulator = HIPSAlertSimulator()
analyzer = SyslogAlertAnalyzer()

# Generate 10 alerts, including some similar ones
alerts = simulator.generate_batch(10, include_similar=True)

# Analyze each alert
for alert in alerts:
    result = analyzer.analyze_alert(alert)
    print(f"Alert: {alert}")
    print(f"Analysis: {result}\n")