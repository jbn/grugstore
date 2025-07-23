# Simplest Possible Content-Addressable Blob Store

[![PyPI version](https://img.shields.io/pypi/v/grugstore.svg)](https://pypi.org/project/grugstore/)

This is a simple content-addressable blob store. It stores blobs of data and
associated metadata. The blobs are stored in a directory hierarchy based on the
base58 encoding of their SHA-256 hash. Metadata is stored as siblings to
the blob file. 

## Installation

Install using uv:
```bash
uv add grugstore
```

Or using pip:
```bash
pip install grugstore
```

## Quick Start

```python
from grugstore import GrugStore

# Create a blob store
gs = GrugStore('some-dir', hierarchy_depth=3)

# Store a blob
hash_str, file_path = gs.store(b'Hello, World!')

# Check if a blob exists
if gs.exists(hash_str):
    # Load the blob
    blob = gs.load_bytes(hash_str)
```

## Core Methods

### Storing and Loading Data

```python
# Store raw bytes - returns (hash_string, file_path)
hash_str, file_path = gs.store(b'Hello, World!')

# Stream from a file-like object (e.g., for large files)
with open('large_file.bin', 'rb') as f:
    hash_str = gs.stream(f)

# Load data back
data = gs.load_bytes(hash_str)
```

### Working with Sibling Files

```python
# Store metadata/sibling files
gs.store_sibling(hash_str, 'json', b'{"key": "value"}')
gs.store_sibling(hash_str, 'txt', b'Additional notes')

# Load sibling data
metadata = gs.load_sibling_bytes(hash_str, 'json')
notes = gs.load_sibling_bytes(hash_str, 'txt')
```

### Checking Existence

```python
# Check if main blob exists
if gs.exists(hash_str):
    print("Blob exists!")

# Check if sibling file exists
if gs.exists(hash_str, 'json'):
    metadata = gs.load_sibling_bytes(hash_str, 'json')
```

### Path Operations

```python
# Get path to a blob (without loading it)
blob_path = gs.path_to(hash_str)

# Get path to a sibling file
metadata_path = gs.path_to(hash_str, 'json')
```

### Iteration and Validation

```python
# Iterate over all blobs (excluding siblings)
for hash_str, file_path in gs.iter_files(no_sibling=True):
    print(f"Found blob: {hash_str}")

# Iterate with sibling information
for hash_str, file_path, sibling_extensions in gs.iter_files():
    print(f"Blob: {hash_str}")
    print(f"Siblings: {sibling_extensions}")  # e.g., {'json', 'txt'}

# Validate integrity of all blobs
for invalid_path in gs.validate_tree():
    print(f"Corrupted file: {invalid_path}")

# Auto-delete corrupted files
for invalid_path in gs.validate_tree(auto_delete=True):
    print(f"Deleted corrupted file: {invalid_path}")
```

## File Layout

GrugStore organizes files in a directory hierarchy based on the base58-encoded SHA-256 hash of the content. The hierarchy depth determines how many subdirectories are created.

### Example Structure (depth=2)

```
some-dir/
├── _tmp/                  # Temporary directory for atomic writes
│   └── tmpfile_12345      # Temporary files during streaming operations
├── 3/                     # First character of hash
│   └── Q/                 # Second character of hash
│       ├── 3QTjz5iqub...  # Main blob file (full hash name)
│       └── 3QTjz5iqub....json  # Sibling metadata file
└── 7/
    └── x/
        ├── 7xB8n2pLm4...  # Another blob (no siblings)
        ├── 7xK9a3vRt6...  # Blob with sibling
        └── 7xK9a3vRt6....json  # JSON sibling file
```

### Key Points

- **Main blobs**: Stored with their full base58-encoded hash as the filename
- **Sibling files**: Same name as the blob but with an extension (e.g., `.json`, `.txt`)
- **Hierarchy**: Based on `hierarchy_depth` parameter (splits hash into subdirectories)
- **_tmp directory**: Used for atomic write operations to ensure data integrity during streaming
