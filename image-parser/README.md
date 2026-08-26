# Native Image Parser

This area contains the C++ executable that receives an immutable local image path from the isolated worker and emits validated JSON findings to standard output. It must not open network connections or mutate the evidence image.
