import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
import re
import pandas as pd

class SyslogAlertAnalyzer:
    def __init__(self):
        # Compile regex patterns once during initialization
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.timestamp_pattern = re.compile(r'\b\d{2}:\d{2}:\d{2}\b')
        self.pid_pattern = re.compile(r'PID: \d+')
        
        # Use more efficient vectorizer settings with adjusted document frequency parameters
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            token_pattern=r'\b\w+\b',
            ngram_range=(1, 2),
            max_features=10000,
            min_df=1,  # Changed from 2 to 1 to handle small alert sets
            max_df=1.0  # Added explicit max_df
        )
        
        # Use more efficient data structures
        self.alert_history = defaultdict(list)
        self.alert_vectors = {}  # Regular dict is faster than defaultdict for this use
        self.alert_counts = defaultdict(lambda: defaultdict(int))
        self.type_counts = defaultdict(int)
        
        # Cache constants
        self.similarity_threshold = 0.85
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
        """Optimized alert preprocessing"""
        message = alert['raw_message']
        # Apply compiled regex patterns
        message = self.ip_pattern.sub('IP_ADDR', message)
        message = self.timestamp_pattern.sub('TIMESTAMP', message)
        message = self.pid_pattern.sub('PID: XXX', message)
        return message.lower()

    def vectorize_alerts(self, alerts, alert_type):
        """Optimized vectorization with batch processing"""
        if not alerts:
            return None
        
        processed_alerts = [self.preprocess_alert(alert) for alert in alerts]
        
        # Only fit the vectorizer once when we first see any alert type
        if not hasattr(self, 'is_fitted'):
            try:
                self.vectorizer.fit(processed_alerts)
                self.is_fitted = True
            except ValueError as e:
                # Fallback for small alert sets
                self.vectorizer.min_df = 1
                self.vectorizer.fit(processed_alerts)
                self.is_fitted = True
        
        # Always use transform instead of fit_transform after initial fit
        return self.vectorizer.transform(processed_alerts)

    def calculate_similarity_score(self, new_alert, alert_type):
        """Optimized similarity calculation"""
        if alert_type not in self.alert_vectors or self.alert_vectors[alert_type] is None:
            return 0.0
            
        new_vector = self.vectorizer.transform([self.preprocess_alert(new_alert)])
        # Use numpy's optimized operations
        similarities = cosine_similarity(new_vector, self.alert_vectors[alert_type])
        return float(np.max(similarities))  # Convert to float for better serialization

    def calculate_uniqueness_score(self, similarity_score, frequency):
        """Calculate uniqueness score based on similarity and frequency"""
        similarity_factor = 1 - similarity_score if similarity_score < self.similarity_threshold else 0
        frequency_factor = 1 / (1 + np.log1p(frequency))
        return (similarity_factor + frequency_factor) / 2

    def analyze_alert(self, alert):
        """Optimized alert analysis"""
        alert_type = alert['type']
        preprocessed_alert = self.preprocess_alert(alert)
        
        # Fast path for first alert of type
        if not self.alert_history[alert_type]:
            result = self._handle_first_alert(alert, alert_type, preprocessed_alert)
            return result
        
        # Calculate scores
        similarity_score = self.calculate_similarity_score(alert, alert_type)
        uniqueness_score = self._calculate_uniqueness(similarity_score, 
                                                    self.alert_counts[alert_type][preprocessed_alert])
        
        # Update state
        self._update_alert_state(alert, alert_type, preprocessed_alert)
        
        # Calculate final score
        return self._calculate_final_scores(alert, alert_type, similarity_score, 
                                         uniqueness_score)

    def _handle_first_alert(self, alert, alert_type, preprocessed_alert):
        """Handle first alert of a type efficiently"""
        self._update_alert_state(alert, alert_type, preprocessed_alert)
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

    def _update_alert_state(self, alert, alert_type, preprocessed_alert):
        """Update internal state with new alert data"""
        self.alert_history[alert_type].append(alert)
        self.alert_counts[alert_type][preprocessed_alert] += 1
        self.type_counts[alert_type] += 1
        self.alert_vectors[alert_type] = self.vectorize_alerts(
            self.alert_history[alert_type], 
            alert_type
        )

    def _calculate_uniqueness(self, similarity_score, frequency):
        """Calculate uniqueness score efficiently"""
        similarity_factor = 1 - similarity_score if similarity_score < self.similarity_threshold else 0
        frequency_factor = 1 / (1 + np.log1p(frequency))
        return (similarity_factor + frequency_factor) / 2

    def _calculate_final_scores(self, alert, alert_type, similarity_score, uniqueness_score):
        """Calculate all final scores for an alert"""
        type_score = self.type_weights[alert_type]
        severity_score = self.severity_weights[alert['severity']]
        
        final_score = (
            type_score * 0.3 +
            severity_score * 0.3 +
            uniqueness_score * 0.4
        )
        
        return {
            'score': final_score,
            'frequency': self.alert_counts[alert_type][self.preprocess_alert(alert)],
            'type_frequency': self.type_counts[alert_type],
            'similarity': similarity_score,
            'uniqueness': uniqueness_score,
            'type_score': type_score,
            'severity_score': severity_score,
            'alert_type': alert_type,
            'severity': alert['severity']
        }

    def get_statistics(self):
        """Get enhanced statistics with optimized calculations"""
        total_alerts = sum(self.type_counts.values())
        
        type_distribution = [
            {
                'alert_type': alert_type,
                'total_alerts': count,
                'unique_patterns': len(self.alert_counts[alert_type]),
                'repetition_ratio': count / len(self.alert_counts[alert_type])
            }
            for alert_type, count in self.type_counts.items()
        ]
        
        return {
            'total_alerts': total_alerts,
            'alerts_by_type': dict(self.type_counts),
            'type_distribution': type_distribution
        }