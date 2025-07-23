import pytest
import tempfile
import shutil
from pathlib import Path
from grugstore import GrugStore
import hashlib
import base58


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
        # Should include both main blob and sibling
        assert len(results) == 2
        filenames = [path.name for _, path in results]
        assert hash_str in filenames
        assert f"{hash_str}.json" in filenames

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
