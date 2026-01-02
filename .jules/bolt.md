## 2024-05-23 - Map Pre-allocation Impact
**Learning:** Pre-allocating maps with `make(map[K]V, len(input))` in hot paths (`SanitizeProperties`) reduced operation time by ~39% (8000ns -> 4900ns) and allocations by ~28% (18 -> 13 allocs/op).
**Action:** Always check loop-based map construction for pre-allocation opportunities, especially in utility functions called thousands of times.
