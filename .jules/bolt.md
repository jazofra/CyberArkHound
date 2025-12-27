## 2024-05-23 - Graph Construction Allocation Overhead
**Learning:** Pre-allocating maps and slices in `OpenGraph` based on input data size (e.g., users, safes, accounts) yields a ~11% performance improvement in graph building. Go's map resizing is expensive, especially for large datasets.
**Action:** Always estimate capacity for maps and slices when the approximate size is known or can be derived from inputs, especially in hot paths like graph generation.
