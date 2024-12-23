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
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│   │Type-specific│    │  TF-IDF     │    │ Similarity  │          │
│   │  Vectors    │───▶│Vectorization│───▶│  Analysis   │          │
│   └─────────────┘    └─────────────┘    └─────────────┘          │
│                              │                                   │
└──────────────────────────────┼───────────────────────────────────┘
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
