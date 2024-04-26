from pathlib import Path
from typing import Callable, Generator
import hashlib
import base58
import contextlib


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def base58_encode(data: bytes) -> str:
    return base58.b58encode(data).decode()


class GrugStore:
    def __init__(
        self,
        root: Path | str,
        hierarchy_depth: int = 3,
        hash_func: Callable = sha256_hash,
        encoding_func: Callable = base58_encode,
        tmp_suffix: str = ".tmp",
    ):
        self._root = Path(root)
        self._hierarchy_depth = hierarchy_depth
        self._hash_func = hash_func
        self._encoding_func = encoding_func
        self._tmp_suffix = tmp_suffix

    def store(self, data: bytes, raise_on_exists: bool = False) -> tuple[str, Path]:
        hash_str = self.calculate_hash_str(data)

        path_file = self.path_from_hash_str(hash_str)
        path_dir = path_file.parent

        if path_file.exists():
            if raise_on_exists:
                raise FileExistsError(f"File already exists: {path_file.as_posix()}")
            return hash_str, path_file

        path_dir.mkdir(parents=True, exist_ok=True)

        # Store the entire hash string not just the remainder less prefix.
        # It saves a lot of time when globbing.
        tmp_path = path_dir / f"{hash_str}{self._tmp_suffix}"
        tmp_path.write_bytes(data)

        # Rename the file to the final name.
        tmp_path.rename(path_file)

        return hash_str, path_file

    def calculate_hash_str(self, data: bytes) -> str:
        hash_bytes = self._hash_func(data)
        return self._encoding_func(hash_bytes)

    def exists(self, hash_str: str) -> bool:
        return self.path_from_hash_str(hash_str).exists()

    def path_from_hash_str(self, hash_str: str) -> Path:
        return self._root.joinpath(
            *[hash_str[i] for i in range(0, self._hierarchy_depth)], hash_str
        )

    def load_bytes(self, hash_str: str) -> bytes:
        path_file = self.path_from_hash_str(hash_str)
        return path_file.read_bytes()

    @contextlib.contextmanager
    def read(self, hash_str: str, mode: str = "rb") -> bytes:
        with self.path_from_hash_str(hash_str).open(mode) as f:
            yield f

    def iter_files(
        self, no_siblings: bool = True
    ) -> Generator[tuple[str, Path], None, None]:

        glob_pattern = "**/*"

        for file_path in self._root.glob(glob_pattern):
            if not file_path.is_file():
                continue

            if file_path.suffix == self._tmp_suffix:
                continue

            if no_siblings and file_path.suffix != "":
                continue

            yield file_path.stem, file_path

    def all_hashes(self) -> set[str]:
        return {hash_str for hash_str, _ in self.iter_files()}

    def store_sibling(
        self,
        hash_str: str,
        ext: str,
        data: bytes,
        overwrite: bool = False,
        blob_must_exist: bool = True,
    ) -> tuple[str, Path]:
        path_file = self.sibling_path(hash_str, ext)

        if blob_must_exist and not self.exists(hash_str):
            raise FileNotFoundError(f"Blob does not exist: {hash_str}")

        if path_file.exists() and not overwrite:
            raise FileExistsError(f"File already exists: {path_file.as_posix()}")

        tmp_path = path_file.with_suffix(self._tmp_suffix)
        tmp_path.write_bytes(data)
        tmp_path.rename(path_file)

        return path_file

    def sibling_path(self, hash_str: str, ext: str) -> Path:
        path_dir = self.path_from_hash_str(hash_str).parent
        return path_dir / f"{hash_str}.{ext}"

    def sibling_exists(self, hash_str: str, ext: str) -> bool:
        return self.sibling_path(hash_str, ext).exists()

    def load_sibling_bytes(self, hash_str: str, ext: str) -> bytes:
        path_file = self.sibling_path(hash_str, ext)
        return path_file.read_bytes()

    @contextlib.contextmanager
    def read_sibling(self, hash_str: str, ext: str, mode: str = "rb") -> bytes:
        with self.sibling_path(hash_str, ext).open(mode) as f:
            yield f
