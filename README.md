# 🛡️ HIPS Alert Analysis System

An advanced Host-based Intrusion Prevention System (HIPS) alert analyzer that uses label-based classification and NLP techniques to intelligently prioritize security alerts based on their type-specific patterns and significance.

## 📋 Overview

This system helps security teams combat alert fatigue by implementing a sophisticated label-based analysis approach:
- Type-specific pattern recognition
- Intelligent similarity scoring within alert categories
- Frequency analysis per alert type
- Severity-based prioritization
- Real-time monitoring capabilities

### 🎯 Key Features

- **Label-based Classification**: Analyzes alerts within their specific type categories
- **Intelligent Vectorization**: TF-IDF based text analysis with n-gram support
- **Pattern Recognition**: Identifies unique and repeated patterns within each alert type
- **Multi-factor Scoring**: Combines type weights, severity, and uniqueness
- **Statistical Analysis**: Comprehensive type-based alert statistics

## 🚀 Getting Started

### Prerequisites

```bash
python 3.8+
numpy
scikit-learn
pandas
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/leo022/hips-alert-analyzer.git
cd hips-alert-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage

1. **View Scoring System Explanation**:
```bash
python main.py --mode explain
```

2. **Run Batch Analysis**:
```bash
python main.py --mode batch --count 15
```

3. **Start Real-time Monitoring**:
```bash
python main.py --mode realtime --interval 3
```

## 🎯 Label-based Scoring System

The system uses a sophisticated three-component scoring algorithm:

### 1. Type-based Scoring (30%)
Each alert type has a predefined risk weight:
- MEMORY_ATTACK: 0.90
- PRIVILEGE_ESCALATION: 0.85
- SYSTEM_TAMPERING: 0.75
- ACCESS_VIOLATION: 0.70
- SUSPICIOUS_EXECUTION: 0.65

### 2. Severity-based Scoring (30%)
Impact level weights:
- Critical: 1.00
- High: 0.80
- Medium: 0.60
- Low: 0.30

### 3. Type-specific Uniqueness (40%)
Calculated within each alert type:
- Similarity Analysis: Compares with previous alerts of the same type
- Frequency Impact: Logarithmic decay for repeated patterns
- Uniqueness Formula: (similarity_factor + frequency_factor) / 2

## 📊 Alert Classification

Alerts are classified into distinct types, each with specific characteristics:

### MEMORY_ATTACK
- Buffer overflows
- Memory injection attempts
- Heap manipulation
- Stack-based attacks

### PRIVILEGE_ESCALATION
- UAC bypass attempts
- Privilege elevation
- Token manipulation
- SYSTEM access attempts

### SYSTEM_TAMPERING
- Registry modifications
- System file changes
- Configuration alterations
- Service manipulations

### ACCESS_VIOLATION
- Unauthorized access attempts
- Directory traversal
- File permission violations
- Resource access violations

### SUSPICIOUS_EXECUTION
- Unusual process launches
- Script execution
- Command line anomalies
- Suspicious child processes

## 📈 Priority Levels

- 🔴 **HIGH** (Score > 0.70)
  - New patterns within type
  - Critical severity alerts
  - High-risk alert types

- 🟡 **MEDIUM** (Score 0.40 - 0.70)
  - Similar but not identical patterns
  - Medium severity alerts
  - Moderate frequency patterns

- 🟢 **LOW** (Score < 0.40)
  - Frequently seen patterns
  - Low severity alerts
  - Low-risk alert types

## 📁 Project Structure

```
project_root/
├── secops/
│   ├── __init__.py
│   ├── alert_simulator.py      # Alert generation with type labels
│   └── syslog_vectorization.py # Label-based analysis engine
├── main.py                     # Main application interface
├── requirements.txt            # Project dependencies
└── README.md                   # This file
```

## 🔧 Configuration

Adjustable parameters:
- `similarity_threshold`: 0.85 (default)
- Type-specific weights
- Severity weights
- Component weight distribution (30/30/40)

## 📈 Example Output

```
🛡️ HIPS ALERT ANALYSIS SYSTEM
========================================
🔴 PRIORITY: HIGH | Type: MEMORY_ATTACK
----------------------------------------
📝 Alert Details:
  • Pattern: Buffer Overflow Attempt
  • Process: svchost.exe (PID: 1234)
  • Severity: Critical
  • Source IP: 192.168.1.100
  • Timestamp: 2024-01-20 15:30:45

📊 Risk Analysis:
  • Final Score: 0.850
  • Type Base Score: 0.900
  • Severity Weight: 1.000
  • Uniqueness Score: 0.950
  • Type Frequency: #1
  • Similarity: 0.150
========================================
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with modern NLP and ML techniques
- Designed for enterprise security teams
- Inspired by real-world SOC challenges

## 📞 Contact

For questions and feedback:

---
Built with ❤️ for the Security Community