"""
Efficient dictionary manager for password wordlist operations.

Implements a singleton pattern to ensure the wordlist is loaded only once into
memory as a frozenset for O(1) case-insensitive lookups. Handles file I/O
errors, encoding issues, and provides performance statistics.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import FrozenSet, Iterator, Optional

from core.config import MAX_WORDLIST_SIZE, WORDLIST_PATH

logger = logging.getLogger(__name__)


class DictionaryStats:
    """Statistics about the loaded dictionary."""

    __slots__ = ("word_count", "file_size_bytes", "load_time_seconds", "file_path")

    def __init__(
        self,
        word_count: int,
        file_size_bytes: int,
        load_time_seconds: float,
        file_path: str,
    ) -> None:
        self.word_count = word_count
        self.file_size_bytes = file_size_bytes
        self.load_time_seconds = load_time_seconds
        self.file_path = file_path

    @property
    def file_size_human(self) -> str:
        """Return human-readable file size."""
        size = self.file_size_bytes
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def __repr__(self) -> str:
        return (
            f"DictionaryStats(words={self.word_count}, "
            f"size={self.file_size_human}, "
            f"load_time={self.load_time_seconds:.3f}s)"
        )


class DictionaryManager:
    """
    Singleton dictionary manager for efficient password wordlist operations.

    The wordlist is loaded into a frozenset with all entries lowercased for
    case-insensitive lookups. Thread-safe initialization ensures the file is
    read exactly once even under concurrent access.
    """

    _instance: Optional["DictionaryManager"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls, wordlist_path: Optional[Path] = None) -> "DictionaryManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self, wordlist_path: Optional[Path] = None) -> None:
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            self._wordlist_path: Path = wordlist_path or WORDLIST_PATH
            self._words: FrozenSet[str] = frozenset()
            self._raw_words: Tuple[str, ...] = ()
            self._last_mtime: Optional[float] = None
            self._stats: Optional[DictionaryStats] = None
            self._loaded: bool = False
            self._load_error: Optional[str] = None
            self._initialized = True

    def load(self, force_reload: bool = False) -> bool:
        """
        Load the wordlist from disk into memory.

        Args:
            force_reload: If True, reload even if already loaded.

        Returns:
            True if the wordlist was loaded successfully, False otherwise.
        """
        file_path = self._wordlist_path
        current_mtime: Optional[float] = None
        try:
            if file_path.exists():
                current_mtime = file_path.stat().st_mtime
        except OSError:
            pass

        if self._loaded and not force_reload:
            if (
                current_mtime is not None
                and self._last_mtime is not None
                and current_mtime == self._last_mtime
            ):
                return True

        start_time = time.perf_counter()

        if not file_path.exists():
            self._load_error = f"Wordlist file not found: {file_path}"
            logger.error(self._load_error)
            return False

        if not file_path.is_file():
            self._load_error = f"Wordlist path is not a file: {file_path}"
            logger.error(self._load_error)
            return False

        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            self._load_error = f"Cannot stat wordlist file: {exc}"
            logger.error(self._load_error)
            return False

        raw_words: list[str] = []
        lower_words: set[str] = set()
        encodings_to_try = ("utf-8-sig", "utf-8", "latin-1", "cp1252")

        for encoding in encodings_to_try:
            try:
                with open(file_path, "r", encoding=encoding, errors="strict") as fh:
                    for line_number, line in enumerate(fh, start=1):
                        stripped = line.strip().lstrip("\ufeff")
                        if not stripped:
                            continue
                        if stripped not in raw_words:
                            raw_words.append(stripped)
                        lower_words.add(stripped.lower())
                        if len(lower_words) >= MAX_WORDLIST_SIZE:
                            logger.warning(
                                "Wordlist truncated at %d words (limit: %d)",
                                len(lower_words),
                                MAX_WORDLIST_SIZE,
                            )
                            break
                break  # Success — stop trying other encodings
            except UnicodeDecodeError:
                raw_words.clear()
                lower_words.clear()
                if encoding == encodings_to_try[-1]:
                    self._load_error = (
                        f"Cannot decode wordlist with any supported encoding: "
                        f"{', '.join(encodings_to_try)}"
                    )
                    logger.error(self._load_error)
                    return False
                continue
            except OSError as exc:
                self._load_error = f"Error reading wordlist file: {exc}"
                logger.error(self._load_error)
                return False

        elapsed = time.perf_counter() - start_time
        self._words = frozenset(lower_words)
        self._raw_words = tuple(raw_words)
        self._last_mtime = current_mtime
        self._stats = DictionaryStats(
            word_count=len(self._words),
            file_size_bytes=file_size,
            load_time_seconds=elapsed,
            file_path=str(file_path),
        )
        self._loaded = True
        self._load_error = None
        logger.info(
            "Wordlist loaded: %d words in %.3fs from %s",
            len(self._words),
            elapsed,
            file_path,
        )
        return True

    def contains(self, password: str) -> bool:
        """
        Check if a password exists in the wordlist (case-insensitive).

        Args:
            password: The password to check.

        Returns:
            True if the password is found in the wordlist.
        """
        if not self._loaded:
            self.load()
        else:
            try:
                if self._wordlist_path.exists() and self._wordlist_path.stat().st_mtime != self._last_mtime:
                    self.load(force_reload=True)
            except OSError:
                pass
        return password.lower() in self._words

    def get_words(self) -> Iterator[str]:
        """
        Iterate over all words in the wordlist preserving exact casing as written.

        Yields:
            Each word in the wordlist with original casing.
        """
        if not self._loaded:
            self.load()
        else:
            try:
                if self._wordlist_path.exists() and self._wordlist_path.stat().st_mtime != self._last_mtime:
                    self.load(force_reload=True)
            except OSError:
                pass
        yield from self._raw_words

    @property
    def is_loaded(self) -> bool:
        """Whether the wordlist has been successfully loaded."""
        return self._loaded

    @property
    def wordlist_path(self) -> Path:
        """Path to the current wordlist file."""
        return self._wordlist_path

    def load_wordlist(self, wordlist_path: Path) -> bool:
        """
        Load a new wordlist file from disk.

        Args:
            wordlist_path: Path to the new wordlist file.

        Returns:
            True if loaded successfully, False otherwise.
        """
        with self._lock:
            self._wordlist_path = Path(wordlist_path)
            self._loaded = False
            return self.load(force_reload=True)

    def reload(self) -> bool:
        """
        Reload the current wordlist file from disk.

        Returns:
            True if reloaded successfully, False otherwise.
        """
        with self._lock:
            return self.load(force_reload=True)

    @property
    def word_count(self) -> int:
        """Number of unique words in the wordlist."""
        return len(self._words)

    @property
    def stats(self) -> Optional[DictionaryStats]:
        """Statistics about the loaded dictionary, or None if not loaded."""
        return self._stats

    @property
    def load_error(self) -> Optional[str]:
        """Error message from the last failed load attempt, or None."""
        return self._load_error

    @classmethod
    def reset(cls) -> None:
        """
        Reset the singleton instance. Useful for testing.
        """
        with cls._lock:
            cls._instance = None
