#!/usr/bin/env python3
"""Example usage of the GrugStore content-addressable blob store."""

from grugstore import GrugStore
import tempfile
import json


def main():
    # Create a temporary directory for demonstration
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Creating blob store in: {temp_dir}")
        
        # Create a blob store with hierarchy depth of 3
        blobstore = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store a simple blob
        data = b"Hello, World!"
        hash_str, file_path = blobstore.store(data)
        print(f"\nStored 'Hello, World!' with hash: {hash_str}")
        print(f"File location: {file_path}")
        
        # Load the blob back
        loaded_data = blobstore.load_bytes(hash_str)
        print(f"Loaded data: {loaded_data.decode()}")
        
        # Store metadata as a sibling file
        metadata = {"author": "example", "timestamp": "2024-01-01"}
        metadata_bytes = json.dumps(metadata).encode()
        sibling_path = blobstore.store_sibling(hash_str, 'json', metadata_bytes)
        print(f"\nStored metadata at: {sibling_path}")
        
        # Load metadata back
        loaded_metadata_bytes = blobstore.load_sibling_bytes(hash_str, 'json')
        loaded_metadata = json.loads(loaded_metadata_bytes)
        print(f"Loaded metadata: {loaded_metadata}")
        
        # Store more blobs
        print("\nStoring additional blobs...")
        blobstore.store(b"First document")
        blobstore.store(b"Second document")
        blobstore.store(b"Third document")
        
        # Iterate over all blobs (excluding siblings)
        print("\nAll blobs in store:")
        for hash_str, file_path in blobstore.iter_files(no_sibling=True):
            print(f"  {hash_str}: {file_path}")
        
        # Iterate over all files (including siblings)
        print("\nAll files in store (including siblings):")
        for hash_str, file_path in blobstore.iter_files(no_sibling=False):
            print(f"  {hash_str}: {file_path}")


if __name__ == "__main__":
    main()