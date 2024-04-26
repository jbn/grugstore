from grugstore import GrugStore
from pathlib import Path
import pytest


def test_grugstore_integration(tmp_path: Path):
    grugstore = GrugStore(tmp_path)

    # The blob =================================================================

    expected_hash_str = grugstore.calculate_hash_str(b"hello world")
    assert not grugstore.exists(expected_hash_str)

    hash_str, path = grugstore.store(b"hello world")
    assert hash_str == expected_hash_str
    assert grugstore.load_bytes(hash_str) == b"hello world"
    assert path.stem == hash_str
    assert grugstore.exists(hash_str)
    assert path == grugstore.path_from_hash_str(hash_str)

    with grugstore.read(hash_str) as f:
        assert f.read() == b"hello world"

    # The storage is by hash so the same data will just return the hash
    got_hash, got_file = grugstore.store(b"hello world")
    assert got_hash == hash_str
    assert got_file == path

    with pytest.raises(FileExistsError):
        grugstore.store(b"hello world", raise_on_exists=True)

    # A sibling ================================================================

    assert not grugstore.sibling_exists(hash_str, "txt")

    grugstore.store_sibling(hash_str, "txt", b"hello sibling")

    assert grugstore.load_sibling_bytes(hash_str, "txt") == b"hello sibling"
    assert grugstore.sibling_exists(hash_str, "txt")
    assert grugstore.sibling_path(hash_str, "txt") == grugstore.path_from_hash_str(
        hash_str
    ).with_suffix(".txt")

    with grugstore.read_sibling(hash_str, "txt") as f:
        assert f.read() == b"hello sibling"

    # Overwrites are more dangerous here without content addressing.
    with pytest.raises(FileExistsError):
        grugstore.store_sibling(hash_str, "txt", b"hello sibling!")
    grugstore.store_sibling(hash_str, "txt", b"hello sibling!", overwrite=True)
    assert grugstore.load_sibling_bytes(hash_str, "txt") == b"hello sibling!"

    # Try to write without the blob
    with pytest.raises(FileNotFoundError):
        grugstore.store_sibling("nope", "txt", b"hello sibling!")

    # Iterate over the blobs====================================================

    # Without siblings
    assert [h for h, _ in grugstore.iter_files()] == [hash_str]

    # With siblings
    assert [h for h, _ in grugstore.iter_files(no_siblings=False)] == [
        hash_str,
        hash_str,
    ]

    # Add another blob
    new_hash_str, _ = grugstore.store(b"goodbye world")
    assert {h for h, _ in grugstore.iter_files(no_siblings=False)} == {
        hash_str,
        new_hash_str,
    }
