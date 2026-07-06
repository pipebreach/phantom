"""Registry of available ecosystems, instantiated per invocation and passed
explicitly, with no module-level mutable state."""

from __future__ import annotations

from phantom.cache import DiskCache
from phantom.ecosystems.base import Ecosystem
from phantom.ecosystems.npm import NpmEcosystem
from phantom.ecosystems.pypi import PyPIEcosystem
from phantom.errors import PhantomError


class Registry:
    def __init__(self) -> None:
        self._ecosystems: dict[str, Ecosystem] = {}

    def register(self, ecosystem: Ecosystem) -> None:
        self._ecosystems[ecosystem.name] = ecosystem

    def get(self, name: str) -> Ecosystem:
        try:
            return self._ecosystems[name]
        except KeyError:
            available = ", ".join(sorted(self._ecosystems)) or "(none)"
            raise PhantomError(
                f"unknown ecosystem {name!r}; available: {available}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._ecosystems)


def build_default_registry(
    cache: DiskCache | None = None, index_url: str | None = None
) -> Registry:
    """Build the registry. ``index_url`` overrides the registry base URL of the
    ecosystem being used (e.g. TestPyPI, or a private index)."""
    registry = Registry()
    registry.register(PyPIEcosystem(cache, index_url))
    registry.register(NpmEcosystem(cache, index_url))
    return registry
