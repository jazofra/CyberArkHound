# Bolt's Journal

## 2024-05-22 - Pre-allocation of slices
**Learning:** Pre-allocating slices in `models.Account` struct enrichment phase yields a ~6.4x performance speedup (~12ms vs ~1.87ms for 10k items) compared to dynamic appending.
**Action:** Always check for slice construction inside loops or where size is known/estimatable and use `make([]T, 0, cap)` pattern.

## 2024-05-22 - Graph Node Map Pre-allocation
**Learning:** Pre-allocating the `Nodes` map in `NewOpenGraphWithCapacity` reduces memory churn and GC pressure, even if CPU gains are marginal (~0.5%).
**Action:** When initializing large maps where the count of items is known (e.g., sum of all source entities), pre-allocate the map capacity.
