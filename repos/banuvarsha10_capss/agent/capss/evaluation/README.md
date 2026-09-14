# Evaluation Module

## Purpose
Provides metrics and benchmarking capabilities for the CAPSS Agent.

## Classes
- `EvaluationMetrics`: Calculates various performance metrics based on experiences and traces.
- `Benchmark`: Runs the agent through standard or comparative scenarios.

## Usage
```python
from capss.evaluation import Benchmark
benchmark = Benchmark(agent)
results = benchmark.run_full_benchmark(contexts)
```
