"""Exception hierarchy. The CLI maps these to exit codes (see ``phantom.cli``)."""

from __future__ import annotations


class PhantomError(Exception):
    """Base class for all phantom errors."""


class FetchError(PhantomError):
    """A network fetch failed."""


class NotFoundError(FetchError):
    """The remote resource does not exist (HTTP 404)."""


class OutOfScopeError(PhantomError):
    """The package exists but cannot be analyzed (e.g. no pure-Python wheel)."""
