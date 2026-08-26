# Filesystem Adapters

Filesystem adapters turn image-level structures into normalized file, directory, and deleted-entry records. The initial native implementation is designed around an explicit adapter interface so filesystem-specific parsers can be enabled independently.
