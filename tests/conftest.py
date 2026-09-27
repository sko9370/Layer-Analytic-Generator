from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
MINI_BUNDLE = FIXTURES / "mini_enterprise.json"


@pytest.fixture(scope="session")
def mini_bundle_path() -> Path:
    """Trimmed ATT&CK Enterprise 19.2 bundle: G0128, S0596, C0041, their techniques and detections,
    plus revoked T1066 and deprecated T1153."""
    return MINI_BUNDLE
