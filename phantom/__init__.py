"""phantom — detect divergence between a package's source and its published artifact.

Core entry point for library use::

    from phantom.core import scan
    from phantom.registry import build_default_registry

    registry = build_default_registry()
    result = scan("some-pkg", "1.2.3", registry.get("pypi"))
"""

__version__ = "0.1.0"
