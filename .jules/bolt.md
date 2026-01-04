## 2024-05-23 - [Graph Construction Allocation Optimization]
**Learning:** Pre-allocating the main `OpenGraph` maps and slices, as well as local lookup maps in `BuildOpenGraph`, significantly reduces memory reallocation overhead. Using heuristics like `safeMembers * 2` for edge capacity provides a safe upper bound.
**Action:** Always check for `make(map)` or `make([]T)` calls inside large data processing functions and ensure they are initialized with a capacity argument derived from input sizes.
