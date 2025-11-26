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
Ava Guardian ♱ (AG♱) - Post-Quantum Cryptography Backends
==========================================================

Centralized PQC backend detection and implementation.
Single source of truth for all post-quantum cryptographic operations.

Supported Algorithms:
- ML-DSA-65 (CRYSTALS-Dilithium): Digital signatures (NIST FIPS 204)
- Kyber-1024 (ML-KEM): Key encapsulation mechanism (NIST FIPS 203)
- SPHINCS+-SHA2-256f: Hash-based signatures (NIST FIPS 205)

This module provides real quantum-resistant implementations via liboqs,
with pqcrypto as a fallback for signatures only.

Standards:
- NIST FIPS 203: ML-KEM (Kyber)
- NIST FIPS 204: ML-DSA (CRYSTALS-Dilithium)
- NIST FIPS 205: SLH-DSA (SPHINCS+)

AI Co-Architects: Eris ⯰ | Eden ♱ | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, cast


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


class KyberUnavailableError(PQCUnavailableError):
    """Raised when Kyber-1024 KEM is requested but not available."""

    pass


class SphincsUnavailableError(PQCUnavailableError):
    """Raised when SPHINCS+-256f is requested but not available."""

    pass


# Backend detection
_DILITHIUM_AVAILABLE = False
_KYBER_AVAILABLE = False
_SPHINCS_AVAILABLE = False
_DILITHIUM_BACKEND: Optional[str] = None
_KYBER_BACKEND: Optional[str] = None
_SPHINCS_BACKEND: Optional[str] = None
_oqs_module: Any = None
_dilithium3_module: Any = None

try:
    # Try liboqs-python first (recommended - fast C implementation)
    import oqs as _oqs_module  # type: ignore[no-redef]

    _DILITHIUM_AVAILABLE = True
    _DILITHIUM_BACKEND = "liboqs"

    # Check for Kyber-1024 support
    try:
        _test_kem = _oqs_module.KeyEncapsulation("Kyber1024")
        _KYBER_AVAILABLE = True
        _KYBER_BACKEND = "liboqs"
        del _test_kem
    except Exception:
        _KYBER_AVAILABLE = False

    # Check for SPHINCS+-SHA2-256f-simple support
    try:
        _test_sig = _oqs_module.Signature("SPHINCS+-SHA2-256f-simple")
        _SPHINCS_AVAILABLE = True
        _SPHINCS_BACKEND = "liboqs"
        del _test_sig
    except Exception:
        _SPHINCS_AVAILABLE = False

except BaseException:
    # BaseException catches:
    # - ImportError: package not installed
    # - RuntimeError: package installed but shared library missing
    # - OSError: library loading issues
    # - SystemExit: liboqs-python auto-install failure (critical for CI)
    # We use BaseException here specifically to catch SystemExit which
    # liboqs-python raises when it fails to auto-install the native library.
    _oqs_module = None
    try:
        # Fall back to pqcrypto (pure Python) - signatures only
        from pqcrypto.sign import dilithium3 as _dilithium3_module  # type: ignore[no-redef]

        _DILITHIUM_AVAILABLE = True
        _DILITHIUM_BACKEND = "pqcrypto"
        # pqcrypto doesn't support Kyber or SPHINCS+
        _KYBER_AVAILABLE = False
        _SPHINCS_AVAILABLE = False
    except BaseException:
        # Same reasoning - catch all failures including SystemExit
        _DILITHIUM_AVAILABLE = False
        _DILITHIUM_BACKEND = None


# Public API for checking availability
DILITHIUM_AVAILABLE: bool = _DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _DILITHIUM_BACKEND
KYBER_AVAILABLE: bool = _KYBER_AVAILABLE
KYBER_BACKEND: Optional[str] = _KYBER_BACKEND
SPHINCS_AVAILABLE: bool = _SPHINCS_AVAILABLE
SPHINCS_BACKEND: Optional[str] = _SPHINCS_BACKEND

# Key sizes from liboqs (authoritative source)
# ML-DSA-65 (Dilithium3)
DILITHIUM_PUBLIC_KEY_BYTES = 1952
DILITHIUM_SECRET_KEY_BYTES = 4032
DILITHIUM_SIGNATURE_BYTES = 3309

# Kyber-1024
KYBER_PUBLIC_KEY_BYTES = 1568
KYBER_SECRET_KEY_BYTES = 3168
KYBER_CIPHERTEXT_BYTES = 1568
KYBER_SHARED_SECRET_BYTES = 32

# SPHINCS+-SHA2-256f-simple
SPHINCS_PUBLIC_KEY_BYTES = 64
SPHINCS_SECRET_KEY_BYTES = 128
SPHINCS_SIGNATURE_BYTES = 49856


def get_pqc_status() -> PQCStatus:
    """
    Get current PQC backend status.

    Returns:
        PQCStatus.AVAILABLE if any PQC backend is available
        PQCStatus.UNAVAILABLE otherwise
    """
    if DILITHIUM_AVAILABLE or KYBER_AVAILABLE or SPHINCS_AVAILABLE:
        return PQCStatus.AVAILABLE
    return PQCStatus.UNAVAILABLE


def get_pqc_backend_info() -> dict:
    """
    Get detailed information about PQC backend availability.

    Returns:
        Dictionary with backend status and details for all algorithms
    """
    return {
        "status": get_pqc_status().value,
        "dilithium_available": DILITHIUM_AVAILABLE,
        "dilithium_backend": DILITHIUM_BACKEND,
        "kyber_available": KYBER_AVAILABLE,
        "kyber_backend": KYBER_BACKEND,
        "sphincs_available": SPHINCS_AVAILABLE,
        "sphincs_backend": SPHINCS_BACKEND,
        "algorithms": {
            "ML-DSA-65": {
                "available": DILITHIUM_AVAILABLE,
                "backend": DILITHIUM_BACKEND,
                "security_level": 3 if DILITHIUM_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": DILITHIUM_PUBLIC_KEY_BYTES,
                        "secret_key": DILITHIUM_SECRET_KEY_BYTES,
                        "signature": DILITHIUM_SIGNATURE_BYTES,
                    }
                    if DILITHIUM_AVAILABLE
                    else None
                ),
            },
            "Kyber-1024": {
                "available": KYBER_AVAILABLE,
                "backend": KYBER_BACKEND,
                "security_level": 5 if KYBER_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": KYBER_PUBLIC_KEY_BYTES,
                        "secret_key": KYBER_SECRET_KEY_BYTES,
                        "ciphertext": KYBER_CIPHERTEXT_BYTES,
                        "shared_secret": KYBER_SHARED_SECRET_BYTES,
                    }
                    if KYBER_AVAILABLE
                    else None
                ),
            },
            "SPHINCS+-256f": {
                "available": SPHINCS_AVAILABLE,
                "backend": SPHINCS_BACKEND,
                "security_level": 5 if SPHINCS_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": SPHINCS_PUBLIC_KEY_BYTES,
                        "secret_key": SPHINCS_SECRET_KEY_BYTES,
                        "signature": SPHINCS_SIGNATURE_BYTES,
                    }
                    if SPHINCS_AVAILABLE
                    else None
                ),
            },
        },
        # Legacy field for backward compatibility
        "backend": DILITHIUM_BACKEND,
        "algorithm": "ML-DSA-65" if DILITHIUM_AVAILABLE else None,
        "security_level": 3 if DILITHIUM_AVAILABLE else None,
    }


@dataclass
class DilithiumKeyPair:
    """
    CRYSTALS-Dilithium post-quantum key pair (ML-DSA-65, Level 3).

    Key Sizes (from liboqs):
        - Private key: 4032 bytes
        - Public key: 1952 bytes
        - Signature: 3309 bytes

    Security: 192-bit quantum security (NIST Security Level 3)
    Standard: NIST FIPS 204 (ML-DSA)
    """

    private_key: bytes  # 4032 bytes for ML-DSA-65
    public_key: bytes  # 1952 bytes for ML-DSA-65


@dataclass
class KyberKeyPair:
    """
    CRYSTALS-Kyber post-quantum key pair (Kyber-1024, Level 5).

    Key Sizes (from liboqs):
        - Secret key: 3168 bytes
        - Public key: 1568 bytes
        - Ciphertext: 1568 bytes
        - Shared secret: 32 bytes

    Security: 256-bit classical / 128-bit quantum security (NIST Security Level 5)
    Standard: NIST FIPS 203 (ML-KEM)
    """

    secret_key: bytes  # 3168 bytes for Kyber-1024
    public_key: bytes  # 1568 bytes for Kyber-1024


@dataclass
class KyberEncapsulation:
    """
    Kyber-1024 key encapsulation result.

    Contains the ciphertext and shared secret from encapsulation.
    """

    ciphertext: bytes  # 1568 bytes
    shared_secret: bytes  # 32 bytes


@dataclass
class SphincsKeyPair:
    """
    SPHINCS+-SHA2-256f-simple post-quantum key pair (Level 5).

    Key Sizes (from liboqs):
        - Secret key: 128 bytes
        - Public key: 64 bytes
        - Signature: 49856 bytes

    Security: 256-bit classical / 128-bit quantum security (NIST Security Level 5)
    Standard: NIST FIPS 205 (SLH-DSA)

    Note: SPHINCS+ signatures are large (~49KB) but provide stateless
    hash-based security with no risk of key reuse vulnerabilities.
    """

    secret_key: bytes  # 128 bytes for SPHINCS+-256f
    public_key: bytes  # 64 bytes for SPHINCS+-256f


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

    if DILITHIUM_BACKEND == "liboqs" and _oqs_module is not None:
        sig = _oqs_module.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return DilithiumKeyPair(private_key=private_key, public_key=public_key)

    elif DILITHIUM_BACKEND == "pqcrypto" and _dilithium3_module is not None:
        public_key, private_key = _dilithium3_module.generate_keypair()
        return DilithiumKeyPair(private_key=private_key, public_key=public_key)

    # Should not reach here if DILITHIUM_AVAILABLE is True
    raise PQCUnavailableError("PQC_UNAVAILABLE: Unknown backend state")


def dilithium_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign message with CRYSTALS-Dilithium (ML-DSA-65).

    Args:
        message: Data to sign
        private_key: Dilithium private key (4032 bytes)

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

    if DILITHIUM_BACKEND == "liboqs" and _oqs_module is not None:
        sig = _oqs_module.Signature("ML-DSA-65")
        sig.secret_key = private_key
        return cast(bytes, sig.sign(message))

    elif DILITHIUM_BACKEND == "pqcrypto" and _dilithium3_module is not None:
        return cast(bytes, _dilithium3_module.sign(message, private_key))

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

    if DILITHIUM_BACKEND == "liboqs" and _oqs_module is not None:
        try:
            sig = _oqs_module.Signature("ML-DSA-65")
            return cast(bool, sig.verify(message, signature, public_key))
        except Exception:
            return False

    elif DILITHIUM_BACKEND == "pqcrypto" and _dilithium3_module is not None:
        try:
            _dilithium3_module.verify(message, signature, public_key)
            return True
        except Exception:
            return False

    raise PQCUnavailableError("PQC_UNAVAILABLE: Unknown backend state")


# ============================================================================
# KYBER-1024 (ML-KEM) KEY ENCAPSULATION MECHANISM
# ============================================================================


def generate_kyber_keypair() -> KyberKeyPair:
    """
    Generate CRYSTALS-Kyber key pair (Kyber-1024, Level 5).

    Kyber-1024 provides IND-CCA2 secure key encapsulation based on the
    Module-LWE (Learning With Errors) problem.

    Returns:
        KyberKeyPair with Kyber-1024 keys

    Raises:
        KyberUnavailableError: If Kyber backend is not available

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> len(keypair.public_key)
        1568
        >>> len(keypair.secret_key)
        3168
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(
            "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if KYBER_BACKEND == "liboqs" and _oqs_module is not None:
        kem = _oqs_module.KeyEncapsulation("Kyber1024")
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return KyberKeyPair(secret_key=secret_key, public_key=public_key)

    raise KyberUnavailableError("KYBER_UNAVAILABLE: Unknown backend state")


def kyber_encapsulate(public_key: bytes) -> KyberEncapsulation:
    """
    Encapsulate a shared secret using Kyber-1024.

    Generates a random shared secret and encapsulates it using the
    recipient's public key. Only the holder of the corresponding
    secret key can decapsulate to recover the shared secret.

    Args:
        public_key: Kyber-1024 public key (1568 bytes)

    Returns:
        KyberEncapsulation with ciphertext and shared secret

    Raises:
        KyberUnavailableError: If Kyber backend is not available
        ValueError: If public_key has incorrect length

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> encap = kyber_encapsulate(keypair.public_key)
        >>> len(encap.ciphertext)
        1568
        >>> len(encap.shared_secret)
        32
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(
            "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if len(public_key) != KYBER_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {KYBER_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )

    if KYBER_BACKEND == "liboqs" and _oqs_module is not None:
        kem = _oqs_module.KeyEncapsulation("Kyber1024")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return KyberEncapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    raise KyberUnavailableError("KYBER_UNAVAILABLE: Unknown backend state")


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decapsulate a shared secret using Kyber-1024.

    Recovers the shared secret from the ciphertext using the secret key.
    This operation is IND-CCA2 secure with implicit rejection.

    Args:
        ciphertext: Kyber-1024 ciphertext (1568 bytes)
        secret_key: Kyber-1024 secret key (3168 bytes)

    Returns:
        Shared secret (32 bytes)

    Raises:
        KyberUnavailableError: If Kyber backend is not available
        ValueError: If ciphertext or secret_key has incorrect length

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> encap = kyber_encapsulate(keypair.public_key)
        >>> shared_secret = kyber_decapsulate(encap.ciphertext, keypair.secret_key)
        >>> shared_secret == encap.shared_secret
        True
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(
            "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if len(ciphertext) != KYBER_CIPHERTEXT_BYTES:
        raise ValueError(
            f"Invalid ciphertext length: expected {KYBER_CIPHERTEXT_BYTES}, "
            f"got {len(ciphertext)}"
        )

    if len(secret_key) != KYBER_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {KYBER_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    if KYBER_BACKEND == "liboqs" and _oqs_module is not None:
        kem = _oqs_module.KeyEncapsulation("Kyber1024")
        kem.secret_key = secret_key
        shared_secret = kem.decap_secret(ciphertext)
        return cast(bytes, shared_secret)

    raise KyberUnavailableError("KYBER_UNAVAILABLE: Unknown backend state")


# ============================================================================
# SPHINCS+-SHA2-256f-simple HASH-BASED SIGNATURES
# ============================================================================


def generate_sphincs_keypair() -> SphincsKeyPair:
    """
    Generate SPHINCS+-SHA2-256f-simple key pair (Level 5).

    SPHINCS+ provides stateless hash-based signatures with no risk of
    key reuse vulnerabilities. The 'f' variant is optimized for fast
    signing at the cost of larger signatures.

    Returns:
        SphincsKeyPair with SPHINCS+-256f keys

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> len(keypair.public_key)
        64
        >>> len(keypair.secret_key)
        128
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(
            "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if SPHINCS_BACKEND == "liboqs" and _oqs_module is not None:
        sig = _oqs_module.Signature("SPHINCS+-SHA2-256f-simple")
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return SphincsKeyPair(secret_key=secret_key, public_key=public_key)

    raise SphincsUnavailableError("SPHINCS_UNAVAILABLE: Unknown backend state")


def sphincs_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign message with SPHINCS+-SHA2-256f-simple.

    SPHINCS+ signatures are large (~49KB) but provide strong security
    guarantees based only on hash function security assumptions.

    Args:
        message: Data to sign (arbitrary length)
        secret_key: SPHINCS+-256f secret key (128 bytes)

    Returns:
        SPHINCS+ signature (49856 bytes)

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
        ValueError: If secret_key has incorrect length

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> signature = sphincs_sign(b"Hello, World!", keypair.secret_key)
        >>> len(signature)
        49856
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(
            "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if len(secret_key) != SPHINCS_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {SPHINCS_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    if SPHINCS_BACKEND == "liboqs" and _oqs_module is not None:
        sig = _oqs_module.Signature("SPHINCS+-SHA2-256f-simple")
        sig.secret_key = secret_key
        return cast(bytes, sig.sign(message))

    raise SphincsUnavailableError("SPHINCS_UNAVAILABLE: Unknown backend state")


def sphincs_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify SPHINCS+-SHA2-256f-simple signature.

    Args:
        message: Original data
        signature: SPHINCS+ signature (49856 bytes)
        public_key: SPHINCS+-256f public key (64 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
        ValueError: If public_key has incorrect length

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> signature = sphincs_sign(b"Hello, World!", keypair.secret_key)
        >>> sphincs_verify(b"Hello, World!", signature, keypair.public_key)
        True
        >>> sphincs_verify(b"Tampered!", signature, keypair.public_key)
        False
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(
            "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
            "Install liboqs-python: pip install liboqs-python"
        )

    if len(public_key) != SPHINCS_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {SPHINCS_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )

    if SPHINCS_BACKEND == "liboqs" and _oqs_module is not None:
        try:
            sig = _oqs_module.Signature("SPHINCS+-SHA2-256f-simple")
            return cast(bool, sig.verify(message, signature, public_key))
        except Exception:
            return False

    raise SphincsUnavailableError("SPHINCS_UNAVAILABLE: Unknown backend state")
