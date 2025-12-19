## 2024-05-23 - [Pre-allocation of Slices in Go]
**Learning:** Pre-allocating slices using `make([]T, 0, capacity)` when the size is known (or bounded) yields significant performance improvements (approx 5x speedup) compared to dynamic appending, especially for large structs.
**Action:** Always look for opportunities to pre-allocate slices when iterating over a collection to build a new one of the same or predictable size.
