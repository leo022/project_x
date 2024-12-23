import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
import re
import pandas as pd

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
        
        # Track type-specific statistics
        self.type_counts = defaultdict(int)
        self.severity_weights = {
            "Low": 0.3,
            "Medium": 0.6,
            "High": 0.8,
            "Critical": 1.0
        }
        
        # Type-specific risk weights
        self.type_weights = {
            "MEMORY_ATTACK": 0.9,
            "PRIVILEGE_ESCALATION": 0.85,
            "SYSTEM_TAMPERING": 0.75,
            "ACCESS_VIOLATION": 0.7,
            "SUSPICIOUS_EXECUTION": 0.65
        }
    
    def preprocess_alert(self, alert):
        """Preprocess the alert message for vectorization"""
        message = alert['raw_message'] if isinstance(alert, dict) else alert
        # Remove timestamps and IP addresses
        message = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDR', message)
        message = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', 'TIMESTAMP', message)
        return message.lower()
    
    def vectorize_alerts(self, alerts):
        processed_alerts = [self.preprocess_alert(alert) for alert in alerts]
        return self.vectorizer.fit_transform(processed_alerts)
    
    def calculate_similarity_score(self, new_alert):
        new_vector = self.vectorizer.transform([self.preprocess_alert(new_alert)])
        similarities = cosine_similarity(new_vector, self.alert_vectors)
        return np.max(similarities)
    
    def calculate_type_score(self, alert_type, frequency):
        """Calculate score based on alert type and its frequency"""
        base_weight = self.type_weights[alert_type]
        frequency_penalty = 1 / (1 + np.log1p(frequency))
        return base_weight * frequency_penalty
    
    def analyze_alert(self, alert):
        """
        Analyze alert with enhanced scoring based on multiple factors
        
        Scoring components:
        1. Base severity score (from severity level)
        2. Type-specific score (from alert type and its frequency)
        3. Similarity score (compared to previous alerts)
        4. Frequency penalty (reduces score for repeated alerts)
        """
        if isinstance(alert, str):
            # Convert string alerts to dummy dict format for backward compatibility
            alert = {
                'raw_message': alert,
                'type': 'UNKNOWN',
                'severity': 'Medium'
            }
        
        # Initialize first alert
        if not self.alert_history:
            self.alert_history.append(alert)
            self.alert_vectors = self.vectorize_alerts(self.alert_history)
            self.alert_counts[alert['raw_message']] += 1
            self.type_counts[alert['type']] += 1
            return {
                'score': 1.0,
                'frequency': 1,
                'type_score': self.type_weights[alert['type']],
                'severity_score': self.severity_weights[alert['severity']],
                'type_frequency': 1
            }
        
        # Calculate similarity with existing alerts
        similarity_score = self.calculate_similarity_score(alert)
        
        # Update history and counters
        self.alert_history.append(alert)
        self.alert_vectors = self.vectorize_alerts(self.alert_history)
        self.alert_counts[alert['raw_message']] += 1
        self.type_counts[alert['type']] += 1
        
        # Calculate component scores
        severity_score = self.severity_weights[alert['severity']]
        type_score = self.calculate_type_score(alert['type'], self.type_counts[alert['type']])
        frequency_factor = 1 / (1 + np.log1p(self.alert_counts[alert['raw_message']]))
        similarity_factor = 1 - similarity_score if similarity_score < self.similarity_threshold else 0
        
        # Calculate final score as weighted average of components
        final_score = (
            severity_score * 0.3 +    # Severity weight
            type_score * 0.3 +        # Type-specific weight
            similarity_factor * 0.2 +  # Uniqueness weight
            frequency_factor * 0.2     # Frequency weight
        )
        
        return {
            'score': final_score,
            'frequency': self.alert_counts[alert['raw_message']],
            'similarity': similarity_score,
            'type_score': type_score,
            'severity_score': severity_score,
            'type_frequency': self.type_counts[alert['type']],
            'alert_type': alert['type'],
            'severity': alert['severity']
        }
    
    def get_statistics(self):
        """Get enhanced statistics including type-based analysis"""
        alert_df = pd.DataFrame({
            'alert': [a['raw_message'] if isinstance(a, dict) else a for a in self.alert_history],
            'type': [a['type'] if isinstance(a, dict) else 'UNKNOWN' for a in self.alert_history],
            'severity': [a['severity'] if isinstance(a, dict) else 'Unknown' for a in self.alert_history]
        })
        
        type_stats = pd.DataFrame({
            'alert_type': list(self.type_counts.keys()),
            'frequency': list(self.type_counts.values())
        })
        
        return {
            'total_alerts': len(self.alert_history),
            'unique_alerts': len(self.alert_counts),
            'type_distribution': type_stats.to_dict('records'),
            'severity_distribution': alert_df['severity'].value_counts().to_dict(),
            'top_frequent_alerts': alert_df['alert'].value_counts().head(5).to_dict()
        }