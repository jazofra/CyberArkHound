## 2024-05-23 - Forgotten Performance Features
**Learning:** Sometimes powerful optimizations are already implemented but unused. `NewOpenGraphWithCapacity` was designed to solve a specific performance bottleneck (allocations) but was abandoned in the usage code.
**Action:** Always check related utility files when optimizing. The tool you need might already exist.
