"""Normalizer interface: reverses a legitimate build transformation so
artifact and source can be compared without false positives."""

from __future__ import annotations

from abc import ABC, abstractmethod

from phantom.models import FileEntry


class Normalizer(ABC):
    @abstractmethod
    def applies_to(self, file: FileEntry) -> bool:
        """Return True if this normalizer can hash this file."""

    @abstractmethod
    def normalized_hash(self, file: FileEntry) -> str:
        """Return a hex digest stable across non-semantic differences."""
