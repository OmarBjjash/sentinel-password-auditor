"""
Tests for dictionary manager and wordlist loading.
"""

from pathlib import Path
import pytest

from core.dictionary_manager import DictionaryManager


class TestDictionaryManager:
    """Tests for core.dictionary_manager module."""

    def test_load_default_wordlist(self) -> None:
        dm = DictionaryManager()
        success = dm.load()
        assert success is True
        assert dm.is_loaded is True
        assert dm.word_count > 0

    def test_contains_common_password(self) -> None:
        dm = DictionaryManager()
        dm.load()
        assert dm.contains("password") is True
        assert dm.contains("123456") is True
        assert dm.contains("qwerty") is True

    def test_contains_case_insensitive(self) -> None:
        dm = DictionaryManager()
        dm.load()
        assert dm.contains("PASSWORD") is True
        assert dm.contains("Password") is True
        assert dm.contains("pAsSwOrD") is True

    def test_not_contains_random(self) -> None:
        dm = DictionaryManager()
        dm.load()
        assert dm.contains("super_unlikely_random_pwd_xyz99") is False

    def test_stats_word_count(self) -> None:
        dm = DictionaryManager()
        dm.load()
        stats = dm.stats
        assert stats is not None
        assert stats.word_count == dm.word_count
        assert stats.file_size_bytes > 0
        assert stats.load_time_seconds >= 0.0

    def test_missing_file_handling(self, tmp_path: Path) -> None:
        missing_file = tmp_path / "non_existent_wordlist.txt"
        dm = DictionaryManager(missing_file)
        success = dm.load()
        assert success is False
        assert dm.is_loaded is False
        assert dm.load_error is not None
        assert "not found" in dm.load_error.lower()

    def test_empty_lines_and_duplicates_ignored(self, temp_wordlist: Path) -> None:
        dm = DictionaryManager(temp_wordlist)
        success = dm.load()
        assert success is True
        # temp_wordlist has 10 unique lower words, plus blank line and duplicate 'PASSWORD'
        assert dm.word_count == 10
        assert dm.contains("baseball") is True
        assert dm.contains("PASSWORD") is True

    def test_reload_dictionary(self, temp_wordlist: Path) -> None:
        dm = DictionaryManager(temp_wordlist)
        dm.load()
        assert dm.word_count == 10

        # Append new word to the file
        with open(temp_wordlist, "a", encoding="utf-8") as f:
            f.write("newpassword999\n")

        # Reload
        success = dm.reload()
        assert success is True
        assert dm.word_count == 11
        assert dm.contains("newpassword999") is True

    def test_load_custom_wordlist(self, tmp_path: Path) -> None:
        dm = DictionaryManager()
        dm.load()

        custom_file = tmp_path / "custom.txt"
        custom_file.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

        success = dm.load_wordlist(custom_file)
        assert success is True
        assert dm.word_count == 3
        assert dm.contains("alpha") is True
        assert dm.contains("beta") is True
        assert dm.contains("gamma") is True
        assert dm.contains("password") is False
