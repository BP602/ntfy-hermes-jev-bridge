"""ntfy -> Jev -> Hermes notification bridge."""

import os
from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the single source; release-please bumps it.
    __version__ = version("ntfy-hermes-jev-bridge")
except PackageNotFoundError:
    __version__ = "0.0.0"

# Container images bake in the commit so builds between releases stay distinguishable in decision records.
GIT_SHA = os.environ.get("BRIDGE_GIT_SHA", "")[:12]
BUILD = f"{__version__}+g{GIT_SHA}" if GIT_SHA else __version__
