import pytest
import tempfile
import shutil
from pathlib import Path
from grugstore import GrugStore
import hashlib
import base58
import io
import uuid
import os


class TestGrugStore:
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_grugstore_initialization(self, temp_dir):
        """Test that GrugStore can be initialized with a directory and hierarchy depth."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        assert store.base_dir == Path(temp_dir)
        assert store.hierarchy_depth == 3

    def test_grugstore_initialization_default_depth(self, temp_dir):
        """Test that GrugStore uses default hierarchy depth if not specified."""
        store = GrugStore(temp_dir)
        assert store.base_dir == Path(temp_dir)
        assert store.hierarchy_depth == 3  # Assuming default is 3

    def test_store_creates_correct_path(self, temp_dir):
        """Test that store() creates the correct directory structure and returns hash."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Hello, World!"

        # Calculate expected hash
        expected_hash = hashlib.sha256(data).digest()
        expected_hash_str = base58.b58encode(expected_hash).decode("ascii")

        # Store the data
        hash_str, file_path = store.store(data)

        # Verify the hash
        assert hash_str == expected_hash_str

        # Verify the file path structure
        assert file_path.exists()
        assert file_path.parent.parent.parent.parent == Path(temp_dir)

        # Verify the directory structure matches the hash
        path_parts = file_path.relative_to(temp_dir).parts
        assert len(path_parts) == 4  # 3 hierarchy levels + filename
        assert path_parts[0] == expected_hash_str[0]
        assert path_parts[1] == expected_hash_str[1]
        assert path_parts[2] == expected_hash_str[2]
        assert path_parts[3] == expected_hash_str

        # Verify the content was written correctly
        assert file_path.read_bytes() == data

    def test_store_same_content_returns_same_path(self, temp_dir):
        """Test that storing the same content twice returns the same path."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Duplicate content"

        hash1, path1 = store.store(data)
        hash2, path2 = store.store(data)

        assert hash1 == hash2
        assert path1 == path2
        assert path1.exists()

    def test_store_noop_when_file_exists(self, temp_dir):
        """Test that store() is a noop when file already exists."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Test content for noop"

        # First store
        hash_str, file_path = store.store(data)
        assert file_path.exists()

        # Get the modification time
        original_mtime = file_path.stat().st_mtime_ns

        # Wait a tiny bit to ensure different mtime if file is rewritten
        import time
        time.sleep(0.01)

        # Store again - should be noop
        hash2, path2 = store.store(data)

        # Should return same hash and path
        assert hash2 == hash_str
        assert path2 == file_path

        # File modification time should not change (noop)
        new_mtime = file_path.stat().st_mtime_ns
        assert new_mtime == original_mtime

    def test_store_different_hierarchy_depths(self, temp_dir):
        """Test store with different hierarchy depths."""
        store2 = GrugStore(temp_dir + "/depth2", hierarchy_depth=2)
        store4 = GrugStore(temp_dir + "/depth4", hierarchy_depth=4)

        data = b"Test data"

        hash2, path2 = store2.store(data)
        hash4, path4 = store4.store(data)

        # Same hash for same data
        assert hash2 == hash4

        # Different path structures
        path2_parts = path2.relative_to(store2.base_dir).parts
        path4_parts = path4.relative_to(store4.base_dir).parts

        assert len(path2_parts) == 3  # 2 hierarchy levels + filename
        assert len(path4_parts) == 5  # 4 hierarchy levels + filename

    def test_load_bytes_retrieves_stored_data(self, temp_dir):
        """Test that load_bytes() correctly retrieves stored data."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Test data to load"

        # Store the data first
        hash_str, _ = store.store(data)

        # Load the data
        loaded_data = store.load_bytes(hash_str)

        assert loaded_data == data

    def test_load_bytes_nonexistent_hash(self, temp_dir):
        """Test that load_bytes() raises FileNotFoundError for non-existent hash."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Try to load a non-existent hash
        fake_hash = base58.b58encode(b"fake hash").decode("ascii")

        with pytest.raises(FileNotFoundError):
            store.load_bytes(fake_hash)

    def test_load_bytes_with_different_hierarchy_depth(self, temp_dir):
        """Test that load_bytes() works correctly with different hierarchy depths."""
        # Store with depth 2
        store2 = GrugStore(temp_dir, hierarchy_depth=2)
        data = b"Data with depth 2"
        hash_str, _ = store2.store(data)

        # Load with same depth
        loaded_data = store2.load_bytes(hash_str)
        assert loaded_data == data

        # Store with depth 4
        store4 = GrugStore(temp_dir + "/depth4", hierarchy_depth=4)
        data4 = b"Data with depth 4"
        hash_str4, _ = store4.store(data4)

        # Load with same depth
        loaded_data4 = store4.load_bytes(hash_str4)
        assert loaded_data4 == data4

    def test_store_sibling_creates_sibling_file(self, temp_dir):
        """Test that store_sibling() creates a sibling file with the given extension."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store main data first
        main_data = b"Main blob data"
        hash_str, main_path = store.store(main_data)

        # Store sibling data
        sibling_data = b'{"key": "value"}'
        sibling_path = store.store_sibling(hash_str, "json", sibling_data)

        # Verify sibling file exists
        assert sibling_path.exists()
        assert sibling_path.name == f"{hash_str}.json"
        assert sibling_path.parent == main_path.parent
        assert sibling_path.read_bytes() == sibling_data

    def test_store_sibling_overwrites_existing(self, temp_dir):
        """Test that store_sibling() overwrites existing sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store main data
        main_data = b"Main blob data"
        hash_str, _ = store.store(main_data)

        # Store sibling data
        original_data = b"Original sibling data"
        store.store_sibling(hash_str, "txt", original_data)

        # Overwrite with new data
        new_data = b"New sibling data"
        sibling_path = store.store_sibling(hash_str, "txt", new_data)

        # Verify new data was written
        assert sibling_path.read_bytes() == new_data

    def test_store_sibling_nonexistent_hash(self, temp_dir):
        """Test that store_sibling() raises FileNotFoundError for non-existent main blob."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Try to store sibling for non-existent hash
        fake_hash = base58.b58encode(b"fake hash").decode("ascii")

        with pytest.raises(FileNotFoundError):
            store.store_sibling(fake_hash, "json", b"data")

    def test_load_sibling_bytes_retrieves_stored_data(self, temp_dir):
        """Test that load_sibling_bytes() correctly retrieves stored sibling data."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store main data
        main_data = b"Main blob data"
        hash_str, _ = store.store(main_data)

        # Store sibling data
        sibling_data = b'{"metadata": "test"}'
        store.store_sibling(hash_str, "json", sibling_data)

        # Load sibling data
        loaded_data = store.load_sibling_bytes(hash_str, "json")
        assert loaded_data == sibling_data

    def test_load_sibling_bytes_nonexistent_sibling(self, temp_dir):
        """Test that load_sibling_bytes() raises FileNotFoundError for non-existent sibling."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store main data
        main_data = b"Main blob data"
        hash_str, _ = store.store(main_data)

        # Try to load non-existent sibling
        with pytest.raises(FileNotFoundError):
            store.load_sibling_bytes(hash_str, "json")

    def test_load_sibling_bytes_nonexistent_main_blob(self, temp_dir):
        """Test that load_sibling_bytes() raises FileNotFoundError for non-existent main blob."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Try to load sibling for non-existent main blob
        fake_hash = base58.b58encode(b"fake hash").decode("ascii")

        with pytest.raises(FileNotFoundError):
            store.load_sibling_bytes(fake_hash, "json")

    def test_iter_files_returns_all_blobs(self, temp_dir):
        """Test that iter_files() returns all stored blobs."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store multiple blobs
        data1 = b"First blob"
        data2 = b"Second blob"
        data3 = b"Third blob"

        hash1, _ = store.store(data1)
        hash2, _ = store.store(data2)
        hash3, _ = store.store(data3)

        # Collect all returned hashes
        returned_hashes = []
        for hash_str, file_path in store.iter_files(no_sibling=True):
            returned_hashes.append(hash_str)
            assert file_path.exists()
            assert file_path.name == hash_str

        # Verify all hashes were returned
        assert set(returned_hashes) == {hash1, hash2, hash3}

    def test_iter_files_no_sibling_excludes_siblings(self, temp_dir):
        """Test that iter_files(no_sibling=True) excludes sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store blob with sibling
        data = b"Main blob"
        hash_str, _ = store.store(data)
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')

        # Iterate with no_sibling=True
        results = list(store.iter_files(no_sibling=True))
        assert len(results) == 1
        assert results[0][0] == hash_str

        # Iterate with no_sibling=False
        results = list(store.iter_files(no_sibling=False))
        # New behavior: returns one entry per hash with sibling extensions
        assert len(results) == 1
        returned_hash, returned_path, siblings = results[0]
        assert returned_hash == hash_str
        assert siblings == {"json"}

    def test_iter_files_empty_store(self, temp_dir):
        """Test that iter_files() returns empty iterator for empty store."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        results = list(store.iter_files())
        assert results == []

    def test_iter_files_with_various_depths(self, temp_dir):
        """Test iter_files() with different hierarchy depths."""
        # Create stores with different depths
        store2 = GrugStore(temp_dir + "/depth2", hierarchy_depth=2)
        store5 = GrugStore(temp_dir + "/depth5", hierarchy_depth=5)

        # Store data in each
        data = b"Test data"
        hash2, _ = store2.store(data)
        hash5, _ = store5.store(data)

        # Verify iter_files works for each depth
        results2 = list(store2.iter_files(no_sibling=True))
        results5 = list(store5.iter_files(no_sibling=True))

        assert len(results2) == 1
        assert len(results5) == 1
        assert results2[0][0] == hash2
        assert results5[0][0] == hash5

    def test_stream_saves_from_file_like_object(self, temp_dir):
        """Test that stream() correctly saves data from a file-like object."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Streaming data test"

        # Create a file-like object
        stream = io.BytesIO(data)

        # Stream the data
        hash_str = store.stream(stream)

        # Calculate expected hash
        expected_hash = hashlib.sha256(data).digest()
        expected_hash_str = base58.b58encode(expected_hash).decode("ascii")

        assert hash_str == expected_hash_str

        # Verify the data was stored correctly
        loaded_data = store.load_bytes(hash_str)
        assert loaded_data == data

        # Verify temp directory is clean
        temp_dir_path = Path(temp_dir) / "_tmp"
        if temp_dir_path.exists():
            assert len(list(temp_dir_path.iterdir())) == 0

    def test_stream_large_file(self, temp_dir):
        """Test streaming a large file in chunks."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Create large data (10MB)
        large_data = b"x" * (10 * 1024 * 1024)
        stream = io.BytesIO(large_data)

        # Stream the data
        hash_str = store.stream(stream)

        # Verify hash
        expected_hash = hashlib.sha256(large_data).digest()
        expected_hash_str = base58.b58encode(expected_hash).decode("ascii")
        assert hash_str == expected_hash_str

        # Verify data was stored
        loaded_data = store.load_bytes(hash_str)
        assert loaded_data == large_data

    def test_stream_cleans_up_on_exception(self, temp_dir):
        """Test that stream() cleans up temporary files on exception."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Create a mock file-like object that raises an exception
        class FailingStream:
            def read(self, size=-1):
                raise IOError("Read failed")

        # Attempt to stream
        with pytest.raises(IOError):
            store.stream(FailingStream())

        # Verify temp directory is clean
        temp_dir_path = Path(temp_dir) / "_tmp"
        if temp_dir_path.exists():
            assert len(list(temp_dir_path.iterdir())) == 0

    def test_stream_handles_empty_stream(self, temp_dir):
        """Test that stream() handles empty streams correctly."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Create empty stream
        stream = io.BytesIO(b"")

        # Stream the data
        hash_str = store.stream(stream)

        # Verify hash of empty data
        expected_hash = hashlib.sha256(b"").digest()
        expected_hash_str = base58.b58encode(expected_hash).decode("ascii")
        assert hash_str == expected_hash_str

    def test_stream_deletes_temp_when_file_exists(self, temp_dir):
        """Test that stream() deletes temp file when target already exists."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        data = b"Duplicate stream data"

        # First, store the data using regular store
        hash_str, file_path = store.store(data)
        assert file_path.exists()

        # Get the modification time
        original_mtime = file_path.stat().st_mtime_ns

        # Create a stream with the same data
        stream = io.BytesIO(data)

        # Stream the data - should delete temp file, not overwrite existing
        hash_str2 = store.stream(stream)

        # Should return same hash
        assert hash_str2 == hash_str

        # File should still exist
        assert file_path.exists()

        # File modification time should not change
        new_mtime = file_path.stat().st_mtime_ns
        assert new_mtime == original_mtime

        # Verify temp directory is clean
        temp_dir_path = Path(temp_dir) / "_tmp"
        if temp_dir_path.exists():
            assert len(list(temp_dir_path.iterdir())) == 0

    def test_validate_tree_with_valid_files(self, temp_dir):
        """Test that validate_tree() returns empty iterator for valid files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store some valid data
        data1 = b"Valid data 1"
        data2 = b"Valid data 2"

        store.store(data1)
        store.store(data2)

        # Validate tree - should return no invalid files
        invalid_files = list(store.validate_tree())
        assert invalid_files == []

    def test_validate_tree_detects_corrupted_file(self, temp_dir):
        """Test that validate_tree() detects files with incorrect hash."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store valid data
        data = b"Original data"
        hash_str, file_path = store.store(data)

        # Corrupt the file by changing its contents
        corrupted_data = b"Corrupted data"
        file_path.write_bytes(corrupted_data)

        # Validate tree - should detect the corrupted file
        invalid_files = list(store.validate_tree())
        assert len(invalid_files) == 1
        assert invalid_files[0] == file_path

    def test_validate_tree_with_auto_delete(self, temp_dir):
        """Test that validate_tree(auto_delete=True) removes invalid files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store valid data
        data = b"Original data"
        hash_str, file_path = store.store(data)

        # Corrupt the file
        file_path.write_bytes(b"Corrupted data")

        # Validate tree with auto_delete
        invalid_files = list(store.validate_tree(auto_delete=True))

        # Should report the invalid file
        assert len(invalid_files) == 1
        assert invalid_files[0] == file_path

        # File should be deleted
        assert not file_path.exists()

    def test_validate_tree_ignores_sibling_files(self, temp_dir):
        """Test that validate_tree() ignores sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store data with sibling
        data = b"Main data"
        hash_str, _ = store.store(data)
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')

        # Validate tree - should not check sibling files
        invalid_files = list(store.validate_tree())
        assert invalid_files == []

    def test_validate_tree_with_misnamed_file(self, temp_dir):
        """Test that validate_tree() detects files with wrong names."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store valid data
        data = b"Test data"
        hash_str, file_path = store.store(data)

        # Rename the file to an incorrect hash
        wrong_hash = base58.b58encode(b"wrong").decode("ascii")
        wrong_path = file_path.parent / wrong_hash
        file_path.rename(wrong_path)

        # Validate tree - should detect the misnamed file
        invalid_files = list(store.validate_tree())
        assert len(invalid_files) == 1
        assert invalid_files[0] == wrong_path

    def test_iter_files_with_sibling_extensions(self, temp_dir):
        """Test that iter_files(no_sibling=False) returns sibling extensions."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store blob with multiple siblings
        data = b"Main blob"
        hash_str, _ = store.store(data)
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')
        store.store_sibling(hash_str, "txt", b"text metadata")
        store.store_sibling(hash_str, "xml", b"<meta>data</meta>")

        # Store another blob with one sibling
        data2 = b"Second blob"
        hash_str2, _ = store.store(data2)
        store.store_sibling(hash_str2, "json", b'{"info": "data"}')

        # Iterate with no_sibling=False
        results = list(store.iter_files(no_sibling=False))

        # Should have 2 entries (one per unique hash)
        assert len(results) == 2

        # Check the results
        result_dict = {r[0]: r for r in results}

        # First blob should have 3 siblings
        assert hash_str in result_dict
        _, _, siblings1 = result_dict[hash_str]
        assert siblings1 == {"json", "txt", "xml"}

        # Second blob should have 1 sibling
        assert hash_str2 in result_dict
        _, _, siblings2 = result_dict[hash_str2]
        assert siblings2 == {"json"}

    def test_iter_files_no_sibling_unchanged(self, temp_dir):
        """Test that iter_files(no_sibling=True) still returns only hash and path."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store blob with sibling
        data = b"Main blob"
        hash_str, _ = store.store(data)
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')

        # Iterate with no_sibling=True
        results = list(store.iter_files(no_sibling=True))

        # Should return tuple of 2 elements
        assert len(results) == 1
        assert len(results[0]) == 2
        assert results[0][0] == hash_str

    def test_iter_files_blob_without_siblings(self, temp_dir):
        """Test that iter_files(no_sibling=False) returns empty set for blobs without siblings."""
        store = GrugStore(temp_dir, hierarchy_depth=3)

        # Store blob without siblings
        data = b"Lonely blob"
        hash_str, _ = store.store(data)

        # Iterate with no_sibling=False
        results = list(store.iter_files(no_sibling=False))

        assert len(results) == 1
        hash_returned, path_returned, siblings = results[0]
        assert hash_returned == hash_str
        assert siblings == set()  # Empty set for no siblings

    def test_path_to_main_blob(self, temp_dir):
        """Test that path_to() returns correct path for main blobs."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Test with a known hash
        test_hash = "Qm1234567890abcdef"
        
        # Get path for main blob
        path = store.path_to(test_hash)
        
        # Verify the path structure
        path_parts = path.relative_to(store.base_dir).parts
        assert len(path_parts) == 4  # 3 hierarchy levels + filename
        assert path_parts[0] == test_hash[0]
        assert path_parts[1] == test_hash[1]
        assert path_parts[2] == test_hash[2]
        assert path_parts[3] == test_hash

    def test_path_to_sibling_file(self, temp_dir):
        """Test that path_to() returns correct path for sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Test with a known hash and extension
        test_hash = "Qm1234567890abcdef"
        extension = "json"
        
        # Get path for sibling file
        path = store.path_to(test_hash, extension)
        
        # Verify the path structure
        path_parts = path.relative_to(store.base_dir).parts
        assert len(path_parts) == 4  # 3 hierarchy levels + filename
        assert path_parts[0] == test_hash[0]
        assert path_parts[1] == test_hash[1]
        assert path_parts[2] == test_hash[2]
        assert path_parts[3] == f"{test_hash}.{extension}"

    def test_path_to_different_hierarchy_depths(self, temp_dir):
        """Test path_to() with different hierarchy depths."""
        # Test with depth 2
        store2 = GrugStore(temp_dir + "/depth2", hierarchy_depth=2)
        test_hash = "QmTest123"
        
        path2 = store2.path_to(test_hash)
        path2_parts = path2.relative_to(store2.base_dir).parts
        assert len(path2_parts) == 3  # 2 hierarchy levels + filename
        assert path2_parts[0] == test_hash[0]
        assert path2_parts[1] == test_hash[1]
        assert path2_parts[2] == test_hash

        # Test with depth 5
        store5 = GrugStore(temp_dir + "/depth5", hierarchy_depth=5)
        path5 = store5.path_to(test_hash)
        path5_parts = path5.relative_to(store5.base_dir).parts
        assert len(path5_parts) == 6  # 5 hierarchy levels + filename
        assert path5_parts[0] == test_hash[0]
        assert path5_parts[1] == test_hash[1]
        assert path5_parts[2] == test_hash[2]
        assert path5_parts[3] == test_hash[3]
        assert path5_parts[4] == test_hash[4]
        assert path5_parts[5] == test_hash

    def test_path_to_short_hash(self, temp_dir):
        """Test path_to() with hash shorter than hierarchy depth."""
        store = GrugStore(temp_dir, hierarchy_depth=5)
        
        # Use a hash shorter than hierarchy depth
        short_hash = "Qm"
        
        path = store.path_to(short_hash)
        path_parts = path.relative_to(store.base_dir).parts
        
        # Should pad with '0'
        assert len(path_parts) == 6  # 5 hierarchy levels + filename
        assert path_parts[0] == "Q"
        assert path_parts[1] == "m"
        assert path_parts[2] == "0"
        assert path_parts[3] == "0"
        assert path_parts[4] == "0"
        assert path_parts[5] == short_hash

    def test_exists_main_blob(self, temp_dir):
        """Test that exists() correctly detects presence of main blobs."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store a blob
        data = b"Test blob for exists"
        hash_str, _ = store.store(data)
        
        # Test that the blob exists
        assert store.exists(hash_str) is True
        
        # Test that a non-existent blob doesn't exist
        fake_hash = base58.b58encode(b"nonexistent").decode("ascii")
        assert store.exists(fake_hash) is False

    def test_exists_sibling_file(self, temp_dir):
        """Test that exists() correctly detects presence of sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store a blob and sibling
        data = b"Main blob data"
        hash_str, _ = store.store(data)
        sibling_data = b'{"metadata": "test"}'
        store.store_sibling(hash_str, "json", sibling_data)
        
        # Test that the sibling exists
        assert store.exists(hash_str, "json") is True
        
        # Test that a non-existent sibling doesn't exist
        assert store.exists(hash_str, "xml") is False

    def test_exists_before_store(self, temp_dir):
        """Test that exists() returns False before storing anything."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Generate a valid-looking hash
        test_data = b"Not yet stored"
        hash_bytes = hashlib.sha256(test_data).digest()
        hash_str = base58.b58encode(hash_bytes).decode("ascii")
        
        # Should not exist before storing
        assert store.exists(hash_str) is False
        
        # Store it
        store.store(test_data)
        
        # Now it should exist
        assert store.exists(hash_str) is True

    def test_exists_with_different_hierarchy_depths(self, temp_dir):
        """Test exists() with different hierarchy depths."""
        # Create store with depth 2
        store2 = GrugStore(temp_dir + "/depth2", hierarchy_depth=2)
        data = b"Test data for depth 2"
        hash_str, _ = store2.store(data)
        
        # Should exist in store2
        assert store2.exists(hash_str) is True
        
        # Create another store with depth 4 at different location
        store4 = GrugStore(temp_dir + "/depth4", hierarchy_depth=4)
        
        # Same hash should not exist in store4 (different location)
        assert store4.exists(hash_str) is False
        
        # Store in store4
        store4.store(data)
        
        # Now should exist in store4
        assert store4.exists(hash_str) is True

    def test_exists_multiple_siblings(self, temp_dir):
        """Test exists() with multiple sibling files."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store main blob
        data = b"Main blob with siblings"
        hash_str, _ = store.store(data)
        
        # Store multiple siblings
        store.store_sibling(hash_str, "json", b'{"type": "json"}')
        store.store_sibling(hash_str, "txt", b"text metadata")
        store.store_sibling(hash_str, "xml", b"<meta>xml</meta>")
        
        # All should exist
        assert store.exists(hash_str) is True
        assert store.exists(hash_str, "json") is True
        assert store.exists(hash_str, "txt") is True
        assert store.exists(hash_str, "xml") is True
        
        # Non-existent extension should not exist
        assert store.exists(hash_str, "pdf") is False

    def test_validate_tree_delete_siblings_with_corrupted_blob(self, temp_dir):
        """Test that validate_tree with delete_siblings removes siblings when blob is corrupted."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store valid data with siblings
        data = b"Original data with siblings"
        hash_str, file_path = store.store(data)
        
        # Store sibling files
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')
        store.store_sibling(hash_str, "txt", b"text metadata")
        store.store_sibling(hash_str, "xml", b"<metadata>xml</metadata>")
        
        # Verify all files exist
        assert file_path.exists()
        assert store.exists(hash_str, "json")
        assert store.exists(hash_str, "txt")
        assert store.exists(hash_str, "xml")
        
        # Corrupt the main blob file
        file_path.write_bytes(b"Corrupted data")
        
        # Validate tree with auto_delete and delete_siblings
        invalid_files = list(store.validate_tree(auto_delete=True, delete_siblings=True))
        
        # Should report the invalid file
        assert len(invalid_files) == 1
        assert invalid_files[0] == file_path
        
        # Main blob should be deleted
        assert not file_path.exists()
        
        # All sibling files should also be deleted
        assert not store.exists(hash_str, "json")
        assert not store.exists(hash_str, "txt")
        assert not store.exists(hash_str, "xml")

    def test_validate_tree_delete_siblings_false_keeps_siblings(self, temp_dir):
        """Test that validate_tree without delete_siblings keeps siblings when blob is deleted."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store valid data with siblings
        data = b"Original data with siblings"
        hash_str, file_path = store.store(data)
        
        # Store sibling files
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')
        store.store_sibling(hash_str, "txt", b"text metadata")
        
        # Verify all files exist
        assert file_path.exists()
        assert store.exists(hash_str, "json")
        assert store.exists(hash_str, "txt")
        
        # Corrupt the main blob file
        file_path.write_bytes(b"Corrupted data")
        
        # Validate tree with auto_delete but without delete_siblings
        invalid_files = list(store.validate_tree(auto_delete=True, delete_siblings=False))
        
        # Should report the invalid file
        assert len(invalid_files) == 1
        assert invalid_files[0] == file_path
        
        # Main blob should be deleted
        assert not file_path.exists()
        
        # Sibling files should still exist
        assert store.exists(hash_str, "json")
        assert store.exists(hash_str, "txt")

    def test_validate_tree_delete_siblings_without_auto_delete(self, temp_dir):
        """Test that delete_siblings has no effect when auto_delete is False."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store valid data with siblings
        data = b"Original data"
        hash_str, file_path = store.store(data)
        store.store_sibling(hash_str, "json", b'{"meta": "data"}')
        
        # Corrupt the main blob file
        file_path.write_bytes(b"Corrupted data")
        
        # Validate tree with delete_siblings but without auto_delete
        invalid_files = list(store.validate_tree(auto_delete=False, delete_siblings=True))
        
        # Should report the invalid file
        assert len(invalid_files) == 1
        
        # Nothing should be deleted
        assert file_path.exists()
        assert store.exists(hash_str, "json")

    def test_validate_tree_delete_siblings_handles_missing_siblings(self, temp_dir):
        """Test that delete_siblings handles cases where siblings don't exist."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store blob without siblings
        data = b"Data without siblings"
        hash_str, file_path = store.store(data)
        
        # Corrupt the main blob file
        file_path.write_bytes(b"Corrupted data")
        
        # This should not raise any errors even though there are no siblings
        invalid_files = list(store.validate_tree(auto_delete=True, delete_siblings=True))
        
        assert len(invalid_files) == 1
        assert not file_path.exists()

    def test_validate_tree_delete_siblings_with_permission_error(self, temp_dir):
        """Test delete_siblings when main blob exists but has wrong content."""
        store = GrugStore(temp_dir, hierarchy_depth=3)
        
        # Store a valid blob with siblings
        data = b"Valid data"
        hash_str, file_path = store.store(data)
        
        # Create sibling files
        store.store_sibling(hash_str, "json", b'{"data": "value"}')
        store.store_sibling(hash_str, "txt", b"text data")
        
        # Now manually create a file with wrong hash but correct name structure
        # This simulates a corrupted file that will fail hash validation
        fake_hash = "FakeHash123"
        fake_path = store.path_to(fake_hash)
        fake_path.parent.mkdir(parents=True, exist_ok=True)
        fake_path.write_bytes(b"This content doesn't match the hash")
        
        # Create siblings for the fake file
        sibling_json = fake_path.parent / f"{fake_hash}.json"
        sibling_txt = fake_path.parent / f"{fake_hash}.txt"
        sibling_json.write_bytes(b'{"fake": "data"}')
        sibling_txt.write_bytes(b"fake text")
        
        # Validate with delete_siblings
        invalid_files = list(store.validate_tree(auto_delete=True, delete_siblings=True))
        
        # Should find the fake file as invalid
        assert fake_path in invalid_files
        
        # Fake file and its siblings should be deleted
        assert not fake_path.exists()
        assert not sibling_json.exists()
        assert not sibling_txt.exists()
        
        # Original valid file and its siblings should still exist
        assert file_path.exists()
        assert store.exists(hash_str, "json")
        assert store.exists(hash_str, "txt")
