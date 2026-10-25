"""Crypto-layer migration logic (Poojita's workstream).

The three surfaces the migration platform (Pranshita) consumes:

* :mod:`.capabilities` - what algorithms/capabilities exist right now
* :mod:`.transition`   - which target modes are feasible and what they need
* :mod:`.metrics`      - measured performance profiles for assessment

Boundary: no asset assessment, no scoring, no recommendations - the
platform's rule-based engine owns those; this layer only answers
crypto-capability questions deterministically.
"""

from .capabilities import CryptoCapabilityCatalog
from .metrics import PerformanceProfile, measure_algorithms, measure_provider
from .transition import MigrationMode, TransitionFeasibility, TransitionOptions

__all__ = [
    "CryptoCapabilityCatalog",
    "MigrationMode",
    "TransitionFeasibility",
    "TransitionOptions",
    "PerformanceProfile",
    "measure_provider",
    "measure_algorithms",
]
