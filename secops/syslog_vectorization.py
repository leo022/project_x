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
        
        # Initialize storage for alerts and vectors
        self.alert_history = defaultdict(list)
        self.alert_vectors = defaultdict(lambda: None)
        self.alert_counts = defaultdict(lambda: defaultdict(int))
        self.type_counts = defaultdict(int)
        self.vectorizer_fitted = False
        
        self.similarity_threshold = 0.85
        
        # Type-specific risk weights
        self.type_weights = {
            "MEMORY_ATTACK": 0.9,
            "PRIVILEGE_ESCALATION": 0.85,
            "SYSTEM_TAMPERING": 0.75,
            "ACCESS_VIOLATION": 0.7,
            "SUSPICIOUS_EXECUTION": 0.65
        }
        
        self.severity_weights = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.3
        }
    
    def preprocess_alert(self, alert):
        """Preprocess the alert message for vectorization"""
        message = alert['raw_message']
        # Remove timestamps, IPs, and PIDs
        message = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDR', message)
        message = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', 'TIMESTAMP', message)
        message = re.sub(r'PID: \d+', 'PID: XXX', message)
        return message.lower()
    
    def fit_vectorizer(self):
        """Fit vectorizer on all existing alerts"""
        all_alerts = []
        for alerts in self.alert_history.values():
            all_alerts.extend([self.preprocess_alert(alert) for alert in alerts])
        if all_alerts:
            self.vectorizer.fit(all_alerts)
            self.vectorizer_fitted = True
    
    def vectorize_alerts(self, alerts, alert_type):
        """Vectorize alerts of a specific type"""
        if not alerts:
            return None
        
        processed_alerts = [self.preprocess_alert(alert) for alert in alerts]
        
        if not self.vectorizer_fitted:
            self.fit_vectorizer()
            
        return self.vectorizer.transform(processed_alerts)
    
    def calculate_similarity_score(self, new_alert, alert_type):
        """Calculate similarity score within the same alert type"""
        if self.alert_vectors[alert_type] is None:
            return 0.0
            
        new_vector = self.vectorizer.transform([self.preprocess_alert(new_alert)])
        similarities = cosine_similarity(new_vector, self.alert_vectors[alert_type])
        return np.max(similarities)
    
    def calculate_uniqueness_score(self, similarity_score, frequency):
        """Calculate uniqueness score based on similarity and frequency"""
        similarity_factor = 1 - similarity_score if similarity_score < self.similarity_threshold else 0
        frequency_factor = 1 / (1 + np.log1p(frequency))
        return (similarity_factor + frequency_factor) / 2
    
    def analyze_alert(self, alert):
        """Analyze alert with enhanced scoring based on type-specific patterns"""
        alert_type = alert['type']
        
        # Initialize first alert of this type
        if not self.alert_history[alert_type]:
            self.alert_history[alert_type].append(alert)
            self.alert_counts[alert_type][self.preprocess_alert(alert)] += 1
            self.type_counts[alert_type] += 1
            self.alert_vectors[alert_type] = self.vectorize_alerts(
                self.alert_history[alert_type], 
                alert_type
            )
            
            return {
                'score': self.type_weights[alert_type],
                'frequency': 1,
                'type_frequency': 1,
                'uniqueness': 1.0,
                'type_score': self.type_weights[alert_type],
                'severity_score': self.severity_weights[alert['severity']],
                'alert_type': alert_type,
                'severity': alert['severity']
            }
        
        # Calculate similarity within the same alert type
        similarity_score = self.calculate_similarity_score(alert, alert_type)
        
        # Update history and counters
        self.alert_history[alert_type].append(alert)
        preprocessed_alert = self.preprocess_alert(alert)
        self.alert_counts[alert_type][preprocessed_alert] += 1
        self.type_counts[alert_type] += 1
        
        # Update vectors
        self.alert_vectors[alert_type] = self.vectorize_alerts(
            self.alert_history[alert_type], 
            alert_type
        )
        
        # Calculate component scores
        uniqueness_score = self.calculate_uniqueness_score(
            similarity_score,
            self.alert_counts[alert_type][preprocessed_alert]
        )
        
        type_score = self.type_weights[alert_type]
        severity_score = self.severity_weights[alert['severity']]
        
        # Calculate final score
        final_score = (
            type_score * 0.3 +          # Base risk weight
            severity_score * 0.3 +       # Severity impact
            uniqueness_score * 0.4       # Uniqueness within type
        )
        
        return {
            'score': final_score,
            'frequency': self.alert_counts[alert_type][preprocessed_alert],
            'type_frequency': self.type_counts[alert_type],
            'similarity': similarity_score,
            'uniqueness': uniqueness_score,
            'type_score': type_score,
            'severity_score': severity_score,
            'alert_type': alert_type,
            'severity': alert['severity']
        }
    
    def get_statistics(self):
        """Get enhanced statistics including type-based analysis"""
        stats = {
            'total_alerts': sum(self.type_counts.values()),
            'alerts_by_type': dict(self.type_counts),
            'type_distribution': []
        }
        
        # Calculate type-specific statistics
        for alert_type in self.type_counts:
            type_alerts = self.alert_history[alert_type]
            unique_patterns = len(self.alert_counts[alert_type])
            
            stats['type_distribution'].append({
                'alert_type': alert_type,
                'total_alerts': self.type_counts[alert_type],
                'unique_patterns': unique_patterns,
                'repetition_ratio': self.type_counts[alert_type] / unique_patterns
            })
        
        return stats