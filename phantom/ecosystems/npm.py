"""npm ecosystem — stub, planned for M2 (FR-10).

Will implement a ``Fetcher`` for registry tarballs (``.tgz``), a
``SourceResolver`` for the ``repository`` field of ``package.json``, and
normalizers for JS minification/transpilation (M3). Registering it in
``phantom.registry`` is all the core needs.
"""

from __future__ import annotations
