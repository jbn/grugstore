from pathlib import Path
from typing import Optional, Tuple, Iterator
import hashlib
import base58


class GrugStore:
    """A simple content-addressable blob store."""

    def __init__(self, base_dir: str | Path, hierarchy_depth: int = 3):
        """Initialize the GrugStore.

        Args:
            base_dir: The base directory where blobs will be stored.
            hierarchy_depth: The depth of the directory hierarchy for storing blobs.
                           Defaults to 3.
        """
        self.base_dir = Path(base_dir)
        self.hierarchy_depth = hierarchy_depth

    def store(self, data: bytes) -> Tuple[str, Path]:
        """Store a blob of data in the content-addressable store.

        Args:
            data: The bytes to store.

        Returns:
            A tuple of (hash_string, file_path) where hash_string is the base58-encoded
            SHA-256 hash of the data and file_path is the Path where the data was stored.
        """
        # Calculate SHA-256 hash
        hash_bytes = hashlib.sha256(data).digest()
        hash_str = base58.b58encode(hash_bytes).decode("ascii")

        # Build the path based on hierarchy depth
        path_parts = []
        for i in range(self.hierarchy_depth):
            if i < len(hash_str):
                path_parts.append(hash_str[i])
            else:
                # If hash is shorter than hierarchy depth, use '0' as padding
                path_parts.append("0")

        # Add the full hash as the filename
        path_parts.append(hash_str)

        # Create the full path
        file_path = self.base_dir.joinpath(*path_parts)

        # Create parent directories if they don't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write the data
        file_path.write_bytes(data)

        return hash_str, file_path

    def load_bytes(self, hash_str: str) -> bytes:
        """Load a blob from the store by its hash.

        Args:
            hash_str: The base58-encoded SHA-256 hash of the blob to load.

        Returns:
            The bytes of the blob.

        Raises:
            FileNotFoundError: If the blob does not exist in the store.
        """
        # Build the path based on hierarchy depth
        path_parts = []
        for i in range(self.hierarchy_depth):
            if i < len(hash_str):
                path_parts.append(hash_str[i])
            else:
                # If hash is shorter than hierarchy depth, use '0' as padding
                path_parts.append("0")

        # Add the full hash as the filename
        path_parts.append(hash_str)

        # Create the full path
        file_path = self.base_dir.joinpath(*path_parts)

        # Check if file exists
        if not file_path.exists():
            raise FileNotFoundError(f"Blob with hash {hash_str} not found in store")

        # Read and return the data
        return file_path.read_bytes()

    def store_sibling(self, hash_str: str, extension: str, data: bytes) -> Path:
        """Store metadata or additional data as a sibling file to the main blob.

        Args:
            hash_str: The base58-encoded SHA-256 hash of the main blob.
            extension: The file extension for the sibling file (without dot).
            data: The bytes to store in the sibling file.

        Returns:
            The Path where the sibling data was stored.

        Raises:
            FileNotFoundError: If the main blob does not exist in the store.
        """
        # First verify the main blob exists
        # Build the path to check if main blob exists
        path_parts = []
        for i in range(self.hierarchy_depth):
            if i < len(hash_str):
                path_parts.append(hash_str[i])
            else:
                path_parts.append("0")
        path_parts.append(hash_str)

        main_blob_path = self.base_dir.joinpath(*path_parts)
        if not main_blob_path.exists():
            raise FileNotFoundError(
                f"Main blob with hash {hash_str} not found in store"
            )

        # Create sibling file path
        sibling_path = main_blob_path.parent / f"{hash_str}.{extension}"

        # Write the sibling data
        sibling_path.write_bytes(data)

        return sibling_path

    def load_sibling_bytes(self, hash_str: str, extension: str) -> bytes:
        """Load a sibling file from the store by its hash and extension.

        Args:
            hash_str: The base58-encoded SHA-256 hash of the main blob.
            extension: The file extension of the sibling file (without dot).

        Returns:
            The bytes of the sibling file.

        Raises:
            FileNotFoundError: If the main blob or sibling file does not exist.
        """
        # First verify the main blob exists
        # Build the path to check if main blob exists
        path_parts = []
        for i in range(self.hierarchy_depth):
            if i < len(hash_str):
                path_parts.append(hash_str[i])
            else:
                path_parts.append("0")
        path_parts.append(hash_str)

        main_blob_path = self.base_dir.joinpath(*path_parts)
        if not main_blob_path.exists():
            raise FileNotFoundError(
                f"Main blob with hash {hash_str} not found in store"
            )

        # Create sibling file path
        sibling_path = main_blob_path.parent / f"{hash_str}.{extension}"

        # Check if sibling file exists
        if not sibling_path.exists():
            raise FileNotFoundError(
                f"Sibling file {hash_str}.{extension} not found in store"
            )

        # Read and return the data
        return sibling_path.read_bytes()

    def iter_files(self, no_sibling: bool = False) -> Iterator[Tuple[str, Path]]:
        """Iterate over all files in the store.

        Args:
            no_sibling: If True, exclude sibling files from the iteration.
                       Only return main blob files. Defaults to False.

        Yields:
            Tuples of (hash_string, file_path) for each file in the store.
        """
        # Create the base directory if it doesn't exist
        if not self.base_dir.exists():
            return

        # Walk through all files in the store
        for path in self.base_dir.rglob("*"):
            if path.is_file():
                filename = path.name

                # If no_sibling is True, skip files with extensions (siblings)
                if no_sibling and "." in filename:
                    continue

                # For main blobs, the filename is the hash
                # For siblings, extract the hash from before the extension
                if "." in filename:
                    hash_str = filename.split(".")[0]
                else:
                    hash_str = filename

                yield hash_str, path


def main() -> None:
    print("Hello from grugstore!")
