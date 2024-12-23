┌──────────────────────────────────────────────────────────────────┐
│                    HIPS Alert Analysis System                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                        Alert Generation                          │
│                    (alert_simulator.py)                          │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│   │Memory Attack│    │Privilege Esc│    │System Tamper│          │
│   └─────────────┘    └─────────────┘    └─────────────┘          │
│          │                  │                  │                 │
└──────────┼──────────────────┼──────────────────┼───────────-─────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Label-based Processing                       │
│                  (syslog_vectorization.py)                       │
│                                                                  │
│   1. Alert Type Classification                                   │
│      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│      │MEMORY_ATTACK│    │PRIVILEGE_ESC│    │ACCESS_VIOL  │      │
│      └─────────────┘    └─────────────┘    └─────────────┘      │
│             │                  │                  │              │
│             ▼                  ▼                  ▼              │
│   2. Text Preprocessing                                         │
│      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│      │Remove Times │    │Standardize  │    │Extract Key  │      │
│      │& IPs        │───▶│  Patterns   │───▶│  Features   │      │
│      └─────────────┘    └─────────────┘    └─────────────┘      │
│             │                                                    │
│             ▼                                                    │
│   3. Type-Specific Vectorization                                │
│      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│      │Separate     │    │  TF-IDF     │    │Feature      │      │
│      │Type Vectors │───▶│Vectorization│───▶│  Matrix     │      │
│      └─────────────┘    └─────────────┘    └─────────────┘      │
│             │                                                    │
│             ▼                                                    │
│   4. Pattern Analysis                                           │
│      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│      │Cosine       │    │Type-Specific│    │Pattern      │      │
│      │Similarity   │───▶│  History    │───▶│  Matching   │      │
│      └─────────────┘    └─────────────┘    └─────────────┘      │
│             │                                                    │
└─────────────┼────────────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────────┐
│                        Score Calculation                         │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│   │Type Weight  │    │  Severity   │    │ Uniqueness  │          │
│   │   (30%)     │    │    (30%)    │    │    (40%)    │          │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘          │
│          │                  │                   │                │
│          └──────────────────┼───────────────────┘                │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Priority Assignment                        │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│   │🔴 HIGH      │    │🟡 MEDIUM    │    │🟢 LOW       │           │
│   │(Score>0.7)  │    │(0.4-0.7)    │    │(Score<0.4)  │          │
│   └─────────────┘    └─────────────┘    └─────────────┘          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Statistical Analysis                          │
│                                                                  │
│   • Type Distribution                                            │
│   • Pattern Recognition                                          │
│   • Frequency Analysis                                           │
│   • Trend Detection                                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

Key Features:
1. Label-based Classification
   - Separate processing for each alert type
   - Type-specific pattern recognition
   - Maintains context within categories

2. Intelligent Scoring
   - Type-based weighting (30%)
   - Severity impact (30%)
   - Pattern uniqueness (40%)

3. Real-time Analysis
   - Continuous monitoring
   - Immediate scoring
   - Pattern detection

4. Statistical Insights
   - Type distribution
   - Pattern frequency
   - Trend analysis


Label-based Processing Details:

1. Alert Type Classification
   - Categorizes incoming alerts by type
   - Maintains separate processing pipelines
   - Enables context-aware analysis

2. Text Preprocessing
   - Removes variable elements (timestamps, IPs)
   - Standardizes alert patterns
   - Extracts key features for analysis

3. Type-Specific Vectorization
   - Creates separate vector spaces per type
   - Applies TF-IDF transformation
   - Maintains type-specific feature matrices

4. Pattern Analysis
   - Calculates within-type similarities
   - Tracks pattern history by type
   - Identifies emerging patterns
