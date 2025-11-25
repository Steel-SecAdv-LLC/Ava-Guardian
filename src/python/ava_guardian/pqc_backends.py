#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Ava Guardian - Post-Quantum Cryptography Backends
==================================================

Centralized PQC backend detection and implementation.
Provides CRYSTALS-Dilithium (ML-DSA-65) signatures via liboqs or pqcrypto.

This module is the single source of truth for PQC availability and operations.
Both dna_guardian_secure.py and crypto_api.py should import from here.

Standards:
- NIST FIPS 204: ML-DSA (CRYSTALS-Dilithium)
- NIST Security Level 3: 192-bit quantum security
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PQCStatus(Enum):
    """PQC backend availability status"""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class PQCUnavailableError(RuntimeError):
    """
    Raised when a PQC algorithm is requested but no backend is available.

    This error is raised instead of silently falling back to classical
    algorithms, ensuring users are aware when PQC protection is not active.
    """

    pass


# Backend detection
_DILITHIUM_AVAILABLE = False
_DILITHIUM_BACKEND: Optional[str] = None
_oqs_module = None
_dilithium3_module = None

try:
    # Try liboqs-python first (recommended - fast C implementation)
    import oqs as _oqs_module

    _DILITHIUM_AVAILABLE = True
    _DILITHIUM_BACKEND = "liboqs"
except (ImportError, RuntimeError, OSError):
    # ImportError: package not installed
    # RuntimeError: package installed but shared library missing
    # OSError: library loading issues
    try:
        # Fall back to pqcrypto (pure Python)
        from pqcrypto.sign import dilithium3 as _dilithium3_module

        _DILITHIUM_AVAILABLE = True
        _DILITHIUM_BACKEND = "pqcrypto"
    except (ImportError, RuntimeError, OSError):
        _DILITHIUM_AVAILABLE = False
        _DILITHIUM_BACKEND = None


# Public API for checking availability
DILITHIUM_AVAILABLE: bool = _DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _DILITHIUM_BACKEND


def get_pqc_status() -> PQCStatus:
    """
    Get current PQC backend status.

    Returns:
        PQCStatus.AVAILABLE if Dilithium backend is available
        PQCStatus.UNAVAILABLE otherwise
    """
    return PQCStatus.AVAILABLE if DILITHIUM_AVAILABLE else PQCStatus.UNAVAILABLE


def get_pqc_backend_info() -> dict:
    """
    Get detailed information about PQC backend availability.

    Returns:
        Dictionary with backend status and details
    """
    return {
        "status": get_pqc_status().value,
        "dilithium_available": DILITHIUM_AVAILABLE,
        "backend": DILITHIUM_BACKEND,
        "algorithm": "ML-DSA-65" if DILITHIUM_AVAILABLE else None,
        "security_level": 3 if DILITHIUM_AVAILABLE else None,
    }


@dataclass
class DilithiumKeyPair:
    """
    CRYSTALS-Dilithium post-quantum key pair (Level 3).

    Key Sizes:
        - Private key: 4000 bytes
        - Public key: 1952 bytes
        - Signature: 3293 bytes

    Security: 192-bit quantum security (NIST Security Level 3)
    Standard: NIST FIPS 204 (ML-DSA)
    """

    private_key: bytes  # 4000 bytes for Dilithium3
    public_key: bytes  # 1952 bytes for Dilithium3


def generate_dilithium_keypair() -> DilithiumKeyPair:
    """
    Generate CRYSTALS-Dilithium key pair (Level 3).

    Returns:
        DilithiumKeyPair with ML-DSA-65 keys

    Raises:
        PQCUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise PQCUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Install liboqs-python (recommended) or pqcrypto: "
            "pip install liboqs-python"
        )

    if DILITHIUM_BACKEND == "liboqs":
        sig = _oqs_module.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return DilithiumKeyPair(private_key=private_key, public_key=public_key)

    elif DILITHIUM_BACKEND == "pqcrypto":
        public_key, private_key = _dilithium3_module.generate_keypair()
        return DilithiumKeyPair(private_key=private_key, public_key=public_key)

    # Should not reach here if DILITHIUM_AVAILABLE is True
    raise PQCUnavailableError("PQC_UNAVAILABLE: Unknown backend state")


def dilithium_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign message with CRYSTALS-Dilithium (ML-DSA-65).

    Args:
        message: Data to sign
        private_key: Dilithium private key (4000 bytes)

    Returns:
        Dilithium signature (3293 bytes)

    Raises:
        PQCUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise PQCUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Install liboqs-python (recommended) or pqcrypto."
        )

    if DILITHIUM_BACKEND == "liboqs":
        sig = _oqs_module.Signature("ML-DSA-65")
        sig.secret_key = private_key
        return sig.sign(message)

    elif DILITHIUM_BACKEND == "pqcrypto":
        return _dilithium3_module.sign(message, private_key)

    raise PQCUnavailableError("PQC_UNAVAILABLE: Unknown backend state")


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify CRYSTALS-Dilithium signature.

    Args:
        message: Original data
        signature: Dilithium signature
        public_key: Dilithium public key (1952 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        PQCUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise PQCUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Install liboqs-python (recommended) or pqcrypto."
        )

    if DILITHIUM_BACKEND == "liboqs":
        try:
            sig = _oqs_module.Signature("ML-DSA-65")
            return sig.verify(message, signature, public_key)
        except Exception:
            return False

    elif DILITHIUM_BACKEND == "pqcrypto":
        try:
            _dilithium3_module.verify(message, signature, public_key)
            return True
        except Exception:
            return False

    raise PQCUnavailableError("PQC_UNAVAILABLE: Unknown backend state")
