"""Crypto-agility layer: provider contract, policies (registry, selection)
and the migration-logic surface exposed to the migration platform.

Import layout keeps dependencies acyclic:

* ``crypto_agility.interfaces``  - abstract contract only (no provider imports)
* ``crypto.*``                   - concrete providers (implement the contract)
* ``crypto_agility.policies``    - registry + selection (import ``crypto.*``)
* ``crypto_agility.migration_logic`` - capability/transition surface for the
  migration platform (import ``crypto_agility.policies``)
"""

from .interfaces.capabilities import ProviderCapabilities
from .interfaces.provider import CryptoProvider

__all__ = ["CryptoProvider", "ProviderCapabilities"]
