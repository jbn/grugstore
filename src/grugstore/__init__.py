from pathlib import Path
from typing import Optional, Tuple, Iterator, BinaryIO, Set, Union
import hashlib
import base58
import uuid
import os


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

    def stream(self, binary_file_like_obj: BinaryIO) -> str:
        """Stream data from a file-like object, computing hash on the fly.

        This method reads from the provided stream in chunks, computes the SHA-256
        hash incrementally, and saves the data to a temporary file. Once complete,
        it moves the file to the appropriate location based on the computed hash.

        Args:
            binary_file_like_obj: A binary file-like object supporting read().

        Returns:
            The base58-encoded SHA-256 hash of the streamed data.

        Raises:
            Exception: Any exception during streaming will cause the temporary
                      file to be deleted.
        """
        # Create temp directory if it doesn't exist
        temp_dir = self.base_dir / "_tmp"
        temp_dir.mkdir(exist_ok=True)

        # Generate a unique temporary filename
        temp_filename = str(uuid.uuid4())
        temp_path = temp_dir / temp_filename

        # Initialize the hash object
        hasher = hashlib.sha256()

        try:
            # Stream data to temporary file while computing hash
            with open(temp_path, "wb") as temp_file:
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk = binary_file_like_obj.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    temp_file.write(chunk)

            # Get the final hash
            hash_bytes = hasher.digest()
            hash_str = base58.b58encode(hash_bytes).decode("ascii")

            # Build the final path
            path_parts = []
            for i in range(self.hierarchy_depth):
                if i < len(hash_str):
                    path_parts.append(hash_str[i])
                else:
                    path_parts.append("0")
            path_parts.append(hash_str)

            final_path = self.base_dir.joinpath(*path_parts)

            # Create parent directories if needed
            final_path.parent.mkdir(parents=True, exist_ok=True)

            # Move the temporary file to the final location
            # If file already exists, just delete the temp file
            if final_path.exists():
                os.unlink(temp_path)
            else:
                os.rename(temp_path, final_path)

            return hash_str

        except Exception:
            # Clean up temporary file on any exception
            if temp_path.exists():
                os.unlink(temp_path)
            raise

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

    def iter_files(
        self, no_sibling: bool = False
    ) -> Iterator[Union[Tuple[str, Path], Tuple[str, Path, Set[str]]]]:
        """Iterate over all files in the store.

        Args:
            no_sibling: If True, exclude sibling files from the iteration and
                       return only (hash_string, file_path) tuples.
                       If False, return (hash_string, file_path, sibling_extensions)
                       tuples where sibling_extensions is a set of extensions.
                       Defaults to False.

        Yields:
            If no_sibling=True: Tuples of (hash_string, file_path) for main blobs only.
            If no_sibling=False: Tuples of (hash_string, file_path, sibling_extensions)
                                for each unique hash, where sibling_extensions is a
                                set of file extensions for that hash.
        """
        # Create the base directory if it doesn't exist
        if not self.base_dir.exists():
            return

        if no_sibling:
            # Original behavior - iterate only main blobs
            for path in self.base_dir.rglob("*"):
                if path.is_file():
                    filename = path.name
                    # Skip files with extensions (siblings)
                    if "." not in filename:
                        yield filename, path
        else:
            # New behavior - group by hash and collect sibling extensions
            hash_info = {}  # hash -> (main_path, set_of_extensions)

            # First pass: collect all files
            for path in self.base_dir.rglob("*"):
                if path.is_file():
                    filename = path.name

                    if "." in filename:
                        # This is a sibling file
                        parts = filename.split(".", 1)
                        hash_str = parts[0]
                        extension = parts[1]

                        if hash_str not in hash_info:
                            hash_info[hash_str] = (None, set())
                        hash_info[hash_str][1].add(extension)
                    else:
                        # This is a main blob
                        hash_str = filename
                        if hash_str not in hash_info:
                            hash_info[hash_str] = (path, set())
                        else:
                            hash_info[hash_str] = (path, hash_info[hash_str][1])

            # Yield results
            for hash_str, (main_path, extensions) in hash_info.items():
                if main_path is not None:
                    yield hash_str, main_path, extensions

    def validate_tree(self, auto_delete: bool = False) -> Iterator[Path]:
        """Validate all blobs in the store by checking their hashes.

        This method iterates over all blob files (not siblings) and verifies
        that the filename matches the SHA-256 hash of the file contents.

        Args:
            auto_delete: If True, automatically delete invalid files.
                        Defaults to False.

        Yields:
            Paths to files that have incorrect hashes.
        """
        # Create the base directory if it doesn't exist
        if not self.base_dir.exists():
            return

        # Walk through all files in the store
        for path in self.base_dir.rglob("*"):
            if path.is_file():
                filename = path.name

                # Skip sibling files (files with extensions)
                if "." in filename:
                    continue

                # The filename should be the hash
                expected_hash_str = filename

                try:
                    # Read the file and compute its hash
                    data = path.read_bytes()
                    actual_hash = hashlib.sha256(data).digest()
                    actual_hash_str = base58.b58encode(actual_hash).decode("ascii")

                    # Check if the hash matches
                    if actual_hash_str != expected_hash_str:
                        # File has incorrect hash
                        yield path
                        if auto_delete:
                            os.unlink(path)

                except Exception:
                    # If we can't read or process the file, it's invalid
                    yield path
                    if auto_delete:
                        try:
                            os.unlink(path)
                        except Exception:
                            pass


def main() -> None:
    print("Hello from grugstore!")
