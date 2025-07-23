"""Example usage of the GrugStore content-addressable blob store."""

from grugstore import GrugStore
import tempfile
import json
import io


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
        sibling_path = blobstore.store_sibling(hash_str, "json", metadata_bytes)
        print(f"\nStored metadata at: {sibling_path}")

        # Load metadata back
        loaded_metadata_bytes = blobstore.load_sibling_bytes(hash_str, "json")
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

        # Iterate over all files (with sibling extensions)
        print("\nAll blobs with their sibling extensions:")
        for hash_str, file_path, sibling_exts in blobstore.iter_files(no_sibling=False):
            print(f"  {hash_str}: {file_path}")
            if sibling_exts:
                print(f"    Siblings: {', '.join(sorted(sibling_exts))}")

        # Demonstrate streaming functionality
        print("\n--- Stream Functionality ---")
        stream_data = b"This is streamed data that will be hashed on the fly"
        stream = io.BytesIO(stream_data)
        streamed_hash = blobstore.stream(stream)
        print(f"Streamed data hash: {streamed_hash}")

        # Verify the streamed data
        loaded_stream_data = blobstore.load_bytes(streamed_hash)
        print(f"Verified streamed data: {loaded_stream_data.decode()}")

        # Demonstrate validation functionality
        print("\n--- Validation Functionality ---")

        # Validate the tree (should find no issues)
        invalid_files = list(blobstore.validate_tree())
        print(f"Invalid files found: {len(invalid_files)}")

        # Create a corrupted file for demonstration
        # WARNING: This is for demonstration only!
        corrupted_hash = "BadHash123"
        corrupted_path = blobstore.base_dir / "B" / "a" / "d" / corrupted_hash
        corrupted_path.parent.mkdir(parents=True, exist_ok=True)
        corrupted_path.write_bytes(b"This content doesn't match the hash")

        # Now validate again
        invalid_files = list(blobstore.validate_tree())
        print(f"Invalid files after corruption: {len(invalid_files)}")
        for invalid in invalid_files:
            print(f"  Invalid: {invalid}")

        # Clean up invalid files
        invalid_files = list(blobstore.validate_tree(auto_delete=True))
        print(f"Cleaned up {len(invalid_files)} invalid files")


if __name__ == "__main__":
    main()
