# Simplest Possible Content-Addressable Blob Store

This is a simple content-addressable blob store. It stores blobs of data and
associated metadata. The blobs are stored in a directory hierarchy based on the
base58 encoding of their SHA-256 hash. Metadata is stored as siblings to
the blob file. 

## Quick Start

```python
from grugstore import GrugStore

# Create a blob store
blobstore = GrugStore('some-dir', hierarchy_depth=3)

# Store a blob
hash_str, file_path = blobstore.store(b'Hello, World!')

# Check if a blob exists
if blobstore.exists(hash_str):
    # Load the blob
    blob = blobstore.load_bytes(hash_str)
```

## Core Methods

### Storing and Loading Data

```python
# Store raw bytes - returns (hash_string, file_path)
hash_str, file_path = blobstore.store(b'Hello, World!')

# Stream from a file-like object (e.g., for large files)
with open('large_file.bin', 'rb') as f:
    hash_str = blobstore.stream(f)

# Load data back
data = blobstore.load_bytes(hash_str)
```

### Working with Sibling Files

```python
# Store metadata/sibling files
blobstore.store_sibling(hash_str, 'json', b'{"key": "value"}')
blobstore.store_sibling(hash_str, 'txt', b'Additional notes')

# Load sibling data
metadata = blobstore.load_sibling_bytes(hash_str, 'json')
notes = blobstore.load_sibling_bytes(hash_str, 'txt')
```

### Checking Existence

```python
# Check if main blob exists
if blobstore.exists(hash_str):
    print("Blob exists!")

# Check if sibling file exists
if blobstore.exists(hash_str, 'json'):
    metadata = blobstore.load_sibling_bytes(hash_str, 'json')
```

### Path Operations

```python
# Get path to a blob (without loading it)
blob_path = blobstore.path_to(hash_str)

# Get path to a sibling file
metadata_path = blobstore.path_to(hash_str, 'json')
```

### Iteration and Validation

```python
# Iterate over all blobs (excluding siblings)
for hash_str, file_path in blobstore.iter_files(no_sibling=True):
    print(f"Found blob: {hash_str}")

# Iterate with sibling information
for hash_str, file_path, sibling_extensions in blobstore.iter_files():
    print(f"Blob: {hash_str}")
    print(f"Siblings: {sibling_extensions}")  # e.g., {'json', 'txt'}

# Validate integrity of all blobs
for invalid_path in blobstore.validate_tree():
    print(f"Corrupted file: {invalid_path}")

# Auto-delete corrupted files
for invalid_path in blobstore.validate_tree(auto_delete=True):
    print(f"Deleted corrupted file: {invalid_path}")
```
