## 2024-05-23 - Graph Construction Allocations
**Learning:** Pre-allocating maps with capacity hint significantly improves performance when dealing with large datasets in Go, but combined with reducing allocations in hot loops (like property sanitization) yields much better results.
**Action:** Always look for `make(map)` inside loops or critical paths and provide capacity hints if known, especially when copying properties.
