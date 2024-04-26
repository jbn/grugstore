# Simplest Possible Content-Addressable Blob Store

This is a simple content-addressable blob store. It stores blobs of data and
associated metadata. The blobs are stored in a directory hierarchy based on the
base58 encoding of their SHA-256 hash. Metadata is stored as siblings to
the blob file. 

```python
# Create a blob store (does nothing)
blobstore = BlobStore('some-dir', hierarchy_depth=3)

# Save a blob  ('some-dir/hash[0]/hash[1]/hash[2]/hash')
hash_str, file_path = blobstore.save(b'Hello, World!')

# Load a blob
blob = blobstore.load(hash_str)

# Save metadata
blobstore.store_sibling(hash_str, 'json', b'{"key": "value"}')

# Load metadata
metadata = blobstore.load_sibling(hash_str, 'json')

# Iter all items in the store
for hash_str, file_path in blobstore.iter_files(no_sibling=True):
    print(hash_str, file_path)

```