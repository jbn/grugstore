# Simplest Possible Content-Addressable Blob Store

<p align="center">
  <img src="grugstore.png" alt="GrugStore Logo" width="512" height="512">
</p>

[![PyPI version](https://img.shields.io/pypi/v/grugstore.svg)](https://pypi.org/project/grugstore/)

This is a simple content-addressable blob store. It stores blobs of data and
associated metadata. The blobs are stored in a directory hierarchy based on the
base58 encoding of their SHA-256 hash. Metadata is stored as siblings to
the blob file. 

## Quick Start

```python
from grugstore import GrugStore

# Create a GrugStore instance
gs = GrugStore('some-dir', hierarchy_depth=3)

# Store a blob
hash_str, file_path = gs.store(b'Hello, World!')

# Check if a blob exists
if gs.exists(hash_str):
    # Load the blob
    blob = gs.load_bytes(hash_str)
```

## Core Methods

### Store Metadata

```python
# Set a README for the store
gs.set_readme("This store contains user avatars and profile images")

# Get the README content
readme_content = gs.get_readme()
```

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

# Auto-delete corrupted files and their siblings
for invalid_path in gs.validate_tree(auto_delete=True, delete_siblings=True):
    print(f"Deleted corrupted file: {invalid_path}")
```

### Filtering and Copying

```python
# Create a filtered copy of the store
def size_filter(hash_str, file_path):
    # Only copy files smaller than 1MB
    return file_path.stat().st_size < 1024 * 1024

# Create a new store with only small files
filtered_gs = gs.filtered_copy('filtered-dir', size_filter)

# The filtered store contains the same hierarchy depth and README
print(f"Hierarchy depth: {filtered_gs.hierarchy_depth}")
print(f"README: {filtered_gs.get_readme()}")

# Example: Copy only specific file types based on sibling extensions
def has_json_metadata(hash_str, file_path):
    # Check if this blob has a JSON sibling
    return gs.exists(hash_str, 'json')

json_only_gs = gs.filtered_copy('json-only-dir', has_json_metadata)

# Example: Copy files matching certain hash patterns
def hash_prefix_filter(hash_str, file_path):
    # Only copy files whose hash starts with 'Q'
    return hash_str.startswith('Q')

q_files_gs = gs.filtered_copy('q-files-dir', hash_prefix_filter)
```

## File Layout

GrugStore organizes files in a hierarchical directory structure based on the base58-encoded SHA-256 hash of the content. Here's an example of what a GrugStore directory looks like with `hierarchy_depth=2`:

```
some-dir/
├── _meta/
│   └── README          # Optional store-level documentation
├── _tmp/                  # Temporary directory for atomic file operations
├── 2/
│   └── X/
│       ├── 2XaBcD...xyz  # The actual blob file (no extension)
│       └── 2XaBcD...xyz.json  # Sibling metadata file
├── 5/
│   └── K/
│       ├── 5Kj9Yz...abc  # Another blob
│       ├── 5Kj9Yz...abc.json  # JSON sibling
│       └── 5Kj9Yz...abc.txt   # Text sibling
└── 8/
    └── R/
        └── 8Rm4Qp...def  # Blob without any sibling files
```

### Directory Structure Details

- **Hash-based hierarchy**: Files are organized using prefixes of their base58-encoded hash. With `hierarchy_depth=2`, the first character becomes the first directory level, the second character becomes the second level.
- **Blob files**: The main content files have no extension and are named with their full hash.
- **Sibling files**: Related metadata or additional content files share the same hash name but include an extension (e.g., `.json`, `.txt`).
- **`_meta/` directory**: Contains store-level metadata like README files.
- **`_tmp/` directory**: Used internally for atomic file operations. Files are first written here and then moved to their final location to ensure write atomicity and prevent partial file corruption.
