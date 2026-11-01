from migration_platform.integrations.crypto_adapter import CryptoAdapter


class MockCapabilityCatalog:

    def available_algorithms(self):
        return [
            {
                "algorithm_id": "rsa4096",
                "name": "RSA-4096",
                "family": "classical",
                "standard": "RSA",
                "security_level": "classical",
                "key_size": 4096,
                "signature_size": None,
                "implementation": "mock-provider",
                "quantum_vulnerable": True,
                "implemented": True,
                "supported_operations": ["sign", "verify"],
                "notes": "Mock test algorithm",
            }
        ]

    def algorithm_details(self, algorithm_id):
        return {"algorithm_id": algorithm_id}

    def check_availability(self, algorithm_id):
        return {
            "algorithm_id": algorithm_id,
            "available": True,
            "reason": "Implemented",
        }


class MockTransitionOptions:

    def check_mode(self, mode):
        class Result:
            def to_dict(self):
                return {
                    "requested_mode": mode,
                    "supported": True,
                    "blockers": [],
                }

        return Result()

    def check_algorithm_for_mode(self, mode, algorithm_id):
        class Result:
            def to_dict(self):
                return {
                    "mode": mode,
                    "algorithm_id": algorithm_id,
                    "supported": True,
                }

        return Result()


def test_available_algorithms():
    adapter = CryptoAdapter(
        MockCapabilityCatalog(),
        MockTransitionOptions()
    )

    algorithms = adapter.available_algorithms()

    assert len(algorithms) == 1
    assert algorithms[0]["algorithm_id"] == "rsa4096"


def test_normalized_algorithms():
    adapter = CryptoAdapter(
        MockCapabilityCatalog(),
        MockTransitionOptions()
    )

    algorithms = adapter.get_normalized_algorithms()

    assert len(algorithms) == 1
    assert algorithms[0].algorithm_id == "rsa4096"
    assert algorithms[0].quantum_vulnerable is True


def test_algorithm_availability():
    adapter = CryptoAdapter(
        MockCapabilityCatalog(),
        MockTransitionOptions()
    )

    result = adapter.check_availability("rsa4096")

    assert result["available"] is True


def test_mode_feasibility():
    adapter = CryptoAdapter(
        MockCapabilityCatalog(),
        MockTransitionOptions()
    )

    result = adapter.check_mode("hybrid")

    assert result["supported"] is True


def test_algorithm_mode_compatibility():
    adapter = CryptoAdapter(
        MockCapabilityCatalog(),
        MockTransitionOptions()
    )

    result = adapter.check_algorithm_for_mode(
        "classical",
        "rsa4096"
    )

    assert result["supported"] is True