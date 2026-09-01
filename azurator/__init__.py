"""Discover and safely rotate shared-key credentials for Azure services."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("azurator")
except PackageNotFoundError:  # pragma: no cover - source trees are normally installed editable
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
