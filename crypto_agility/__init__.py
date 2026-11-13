"""Crypto-agility layer: provider contract, policies (registry, selection)
and the migration-logic surface exposed to the migration platform.

Import layout keeps dependencies acyclic:

* ``crypto_agility.interfaces``  - abstract contract only (no provider imports)
* ``crypto.*``                   - concrete providers (implement the contract)
* ``crypto_agility.policies``    - registry + selection (import ``crypto.*``)
* ``crypto_agility.migration_logic`` - capability/transition surface for the
  migration platform (import ``crypto_agility.policies``)
"""

# crypto_agility.interfaces imports crypto.keys, which initializes the crypto
# package, whose providers import crypto_agility.interfaces back. Loading
# crypto first lets "import crypto_agility" work as the first import too.
import crypto  # noqa: F401

from .interfaces.capabilities import ProviderCapabilities
from .interfaces.provider import CryptoProvider

__all__ = ["CryptoProvider", "ProviderCapabilities"]
