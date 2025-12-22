## 2024-05-23 - Slice Pre-allocation for Large Structs
**Learning:** Appending large value structs (like `models.Account`, ~200-300 bytes) to a slice without pre-allocation causes significant overhead due to repeated resizing and copying of the entire dataset.
**Action:** Always pre-allocate slices when the upper bound is known (e.g., from a previous "skeleton" fetch phase). Benchmarks showed a ~6x speedup (14ms -> 2.4ms for 10k items).
