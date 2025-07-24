from pathlib import Path
from typing import Optional, Tuple, Iterator, BinaryIO, Set, Union
import hashlib
import base58
import uuid
import os
from contextlib import contextmanager


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

        # Create _meta directory if it doesn't exist
        self._meta_dir = self.base_dir / "_meta"
        self._meta_dir.mkdir(parents=True, exist_ok=True)

    def __str__(self) -> str:
        """Return a human-readable string representation of the GrugStore."""
        return f"GrugStore({self.base_dir})"

    def __repr__(self) -> str:
        """Return a detailed string representation of the GrugStore."""
        return f"GrugStore(base_dir={self.base_dir!r}, hierarchy_depth={self.hierarchy_depth})"

    def _hash_bytes(self, data: bytes) -> str:
        """Calculate the base58-encoded SHA-256 hash of bytes.

        Args:
            data: The bytes to hash.

        Returns:
            The base58-encoded SHA-256 hash string.
        """
        hash_bytes = hashlib.sha256(data).digest()
        return base58.b58encode(hash_bytes).decode("ascii")

    def _hash_file(self, file_path: Path) -> str:
        """Calculate the base58-encoded SHA-256 hash of a file.

        Args:
            file_path: Path to the file to hash.

        Returns:
            The base58-encoded SHA-256 hash string.
        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)

        hash_bytes = hasher.digest()
        return base58.b58encode(hash_bytes).decode("ascii")

    def store(self, data: bytes) -> Tuple[str, Path]:
        """Store a blob of data in the content-addressable store.

        Args:
            data: The bytes to store.

        Returns:
            A tuple of (hash_string, file_path) where hash_string is the base58-encoded
            SHA-256 hash of the data and file_path is the Path where the data was stored.
        """
        # Calculate SHA-256 hash
        hash_str = self._hash_bytes(data)

        # Get the path using path_to method
        file_path = self.path_to(hash_str)

        # If file already exists, return without writing (noop)
        if file_path.exists():
            return hash_str, file_path

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

            # Get the final path using path_to method
            final_path = self.path_to(hash_str)

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

    def path_to(self, content_hash: str, extension: Optional[str] = None) -> Path:
        """Get the path to a blob or sibling file.

        Args:
            content_hash: The base58-encoded SHA-256 hash of the blob.
            extension: Optional file extension for sibling files (without dot).
                      If None, returns path to the main blob.

        Returns:
            The Path to the blob or sibling file.
        """
        # Build the path based on hierarchy depth
        path_parts = []
        for i in range(self.hierarchy_depth):
            if i < len(content_hash):
                path_parts.append(content_hash[i])
            else:
                # If hash is shorter than hierarchy depth, use '0' as padding
                path_parts.append("0")

        # Add the full hash as the filename
        if extension is None:
            path_parts.append(content_hash)
        else:
            # For sibling files, we need to go to the parent directory
            # and add the filename with extension
            path_parts.append(f"{content_hash}.{extension}")

        # Create the full path
        return self.base_dir.joinpath(*path_parts)

    def exists(self, content_hash: str, extension: Optional[str] = None) -> bool:
        """Check if a blob or sibling file exists in the store.

        Args:
            content_hash: The base58-encoded SHA-256 hash of the blob.
            extension: Optional file extension for sibling files (without dot).
                      If None, checks for the main blob.

        Returns:
            True if the file exists, False otherwise.
        """
        file_path = self.path_to(content_hash, extension)
        return file_path.exists()

    def load_bytes(self, hash_str: str) -> bytes:
        """Load a blob from the store by its hash.

        Args:
            hash_str: The base58-encoded SHA-256 hash of the blob to load.

        Returns:
            The bytes of the blob.

        Raises:
            FileNotFoundError: If the blob does not exist in the store.
        """
        file_path = self.path_to(hash_str)

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
        if not self.exists(hash_str):
            raise FileNotFoundError(
                f"Main blob with hash {hash_str} not found in store"
            )

        # Get sibling file path
        sibling_path = self.path_to(hash_str, extension)

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
        if not self.exists(hash_str):
            raise FileNotFoundError(
                f"Main blob with hash {hash_str} not found in store"
            )

        # Check if sibling file exists
        if not self.exists(hash_str, extension):
            raise FileNotFoundError(
                f"Sibling file {hash_str}.{extension} not found in store"
            )

        # Get sibling file path and read data
        sibling_path = self.path_to(hash_str, extension)
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
                    # Skip files in special directories
                    if "_meta" in path.parts or "_tmp" in path.parts:
                        continue
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
                    # Skip files in special directories
                    if "_meta" in path.parts or "_tmp" in path.parts:
                        continue
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

    def validate_tree(
        self, auto_delete: bool = False, delete_siblings: bool = False
    ) -> Iterator[Path]:
        """Validate all blobs in the store by checking their hashes.

        This method iterates over all blob files (not siblings) and verifies
        that the filename matches the SHA-256 hash of the file contents.

        Args:
            auto_delete: If True, automatically delete invalid files.
                        Defaults to False.
            delete_siblings: If True and auto_delete is True, also delete
                           sibling files when the main blob is invalid.
                           Defaults to False.

        Yields:
            Paths to files that have incorrect hashes.
        """
        # Use iter_files to iterate over all main blobs (excluding siblings)
        for expected_hash_str, file_path in self.iter_files(no_sibling=True):
            try:
                # Read the file and compute its hash
                actual_hash_str = self._hash_file(file_path)

                # Check if the hash matches
                if actual_hash_str != expected_hash_str:
                    # File has incorrect hash
                    yield file_path
                    if auto_delete:
                        os.unlink(file_path)

                        # Delete sibling files if requested
                        if delete_siblings:
                            # Find and delete all sibling files
                            parent_dir = file_path.parent
                            sibling_pattern = f"{expected_hash_str}.*"
                            for sibling in parent_dir.glob(sibling_pattern):
                                if sibling.is_file() and sibling != file_path:
                                    try:
                                        os.unlink(sibling)
                                    except Exception:
                                        pass

            except Exception:
                # If we can't read or process the file, it's invalid
                yield file_path
                if auto_delete:
                    try:
                        os.unlink(file_path)

                        # Delete sibling files if requested
                        if delete_siblings:
                            # Find and delete all sibling files
                            parent_dir = file_path.parent
                            sibling_pattern = f"{expected_hash_str}.*"
                            for sibling in parent_dir.glob(sibling_pattern):
                                if sibling.is_file() and sibling != file_path:
                                    try:
                                        os.unlink(sibling)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

    def set_readme(self, content: str) -> None:
        """Set the README content for this GrugStore.

        Args:
            content: The README content to store.
        """
        readme_path = self._meta_dir / "README"
        readme_path.write_text(content, encoding="utf-8")

    def get_readme(self) -> str:
        """Get the README content for this GrugStore.

        Returns:
            The README content, or empty string if not set.

        Raises:
            FileNotFoundError: If the README file does not exist.
        """
        readme_path = self._meta_dir / "README"
        if not readme_path.exists():
            raise FileNotFoundError(f"README file not found at {readme_path}")
        return readme_path.read_text(encoding="utf-8")

    def filtered_copy(self, new_gs_dir: Union[str, Path], filter_func) -> "GrugStore":
        """Create a filtered copy of this GrugStore.

        Args:
            new_gs_dir: The directory for the new GrugStore.
            filter_func: A function that takes (hash_str, file_path) and returns
                        True if the file should be copied.

        Returns:
            A new GrugStore instance containing only the filtered files.
        """
        # Create the new GrugStore
        new_gs = GrugStore(new_gs_dir, self.hierarchy_depth)

        # Copy filtered files and their siblings
        for hash_str, file_path, sibling_extensions in self.iter_files(
            no_sibling=False
        ):
            # Check if this file passes the filter
            if filter_func(hash_str, file_path):
                # Copy the main blob
                data = self.load_bytes(hash_str)
                new_gs.store(data)

                # Copy all sibling files
                for ext in sibling_extensions:
                    try:
                        sibling_data = self.load_sibling_bytes(hash_str, ext)
                        new_gs.store_sibling(hash_str, ext, sibling_data)
                    except FileNotFoundError:
                        # Skip if sibling file doesn't exist
                        pass

        # Copy _meta/README if it exists
        try:
            readme_content = self.get_readme()
            new_gs.set_readme(readme_content)
        except FileNotFoundError:
            # No README to copy
            pass

        return new_gs

    def copy_file(self, input_path: Union[str, Path]) -> Tuple[str, Path]:
        """Copy a file into the GrugStore.

        Args:
            input_path: Path to the file to copy.

        Returns:
            A tuple of (hash_string, file_path) where hash_string is the base58-encoded
            SHA-256 hash of the file and file_path is the Path where the file was stored.

        Raises:
            FileNotFoundError: If the input file does not exist.
        """
        import shutil

        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Calculate hash of the file
        hash_str = self._hash_file(input_path)

        # Get target path
        target_path = self.path_to(hash_str)

        # If file already exists, just return
        if target_path.exists():
            return hash_str, target_path

        # Create parent directories if needed
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy the file
        shutil.copy2(input_path, target_path)

        return hash_str, target_path

    def move_file(self, input_path: Union[str, Path]) -> Tuple[str, Path]:
        """Move a file into the GrugStore.

        Args:
            input_path: Path to the file to move.

        Returns:
            A tuple of (hash_string, file_path) where hash_string is the base58-encoded
            SHA-256 hash of the file and file_path is the Path where the file was stored.

        Raises:
            FileNotFoundError: If the input file does not exist.
        """
        import shutil

        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Calculate hash of the file
        hash_str = self._hash_file(input_path)

        # Get target path
        target_path = self.path_to(hash_str)

        # If file already exists, just delete the source
        if target_path.exists():
            os.unlink(input_path)
            return hash_str, target_path

        # Create parent directories if needed
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the file
        shutil.move(str(input_path), str(target_path))

        return hash_str, target_path

    @contextmanager
    def read(self, hash_str: str):
        """Open a blob as a file object for reading in binary mode.

        This method returns a context manager that opens the actual file
        for reading in binary mode.

        Args:
            hash_str: The base58-encoded SHA-256 hash of the blob to read.

        Yields:
            An open file object in binary read mode.

        Raises:
            FileNotFoundError: If the blob does not exist in the store.

        Example:
            with gs.read(hash_str) as f:
                content = f.read()
        """
        file_path = self.path_to(hash_str)

        if not file_path.exists():
            raise FileNotFoundError(f"Blob with hash {hash_str} not found in store")

        with open(file_path, "rb") as f:
            yield f

    @contextmanager
    def write(self):
        """Create a new blob by writing to a temporary file.

        This method returns a context manager that provides a file object for
        writing. Data is written to a temporary file, and upon successful
        completion (no exceptions), the file is moved to its final location
        based on the computed hash.

        Yields:
            A tuple of (file_object, hash_getter) where:
            - file_object: An open file object in binary write mode
            - hash_getter: A callable that returns the hash string when called
                          (only valid after the file is closed)

        Returns:
            The base58-encoded SHA-256 hash of the written data (after context exits).

        Example:
            with gs.write() as (f, get_hash):
                f.write(b"Hello, world!")
            hash_str = get_hash()
        """
        # Create temp directory if it doesn't exist
        temp_dir = self.base_dir / "_tmp"
        temp_dir.mkdir(exist_ok=True)

        # Generate a unique temporary filename
        temp_filename = str(uuid.uuid4())
        temp_path = temp_dir / temp_filename

        # Initialize the hash object
        hasher = hashlib.sha256()
        hash_str = None

        # Create a wrapper that updates the hash as data is written
        class HashingFileWrapper:
            def __init__(self, file_obj):
                self.file_obj = file_obj

            def write(self, data):
                hasher.update(data)
                return self.file_obj.write(data)

            def __getattr__(self, name):
                return getattr(self.file_obj, name)

        try:
            with open(temp_path, "wb") as temp_file:
                wrapped_file = HashingFileWrapper(temp_file)

                def get_hash():
                    nonlocal hash_str
                    if hash_str is None:
                        # File must be closed first
                        raise RuntimeError("Cannot get hash until file is closed")
                    return hash_str

                yield wrapped_file, get_hash

            # Get the final hash
            hash_bytes = hasher.digest()
            hash_str = base58.b58encode(hash_bytes).decode("ascii")

            # Get the final path using path_to method
            final_path = self.path_to(hash_str)

            # Create parent directories if needed
            final_path.parent.mkdir(parents=True, exist_ok=True)

            # Move the temporary file to the final location
            # If file already exists, just delete the temp file
            if final_path.exists():
                os.unlink(temp_path)
            else:
                os.rename(temp_path, final_path)

        except Exception:
            # Clean up temporary file on any exception
            if temp_path.exists():
                os.unlink(temp_path)
            raise


def main() -> None:
    print("Hello from grugstore!")
