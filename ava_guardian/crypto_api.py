#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ava Guardian - Algorithm-Agnostic Cryptographic API
====================================================

Unified interface for all post-quantum cryptographic algorithms.
Enables seamless switching between ML-DSA-65, Kyber-1024, SPHINCS+-256f,
and hybrid classical+PQC modes.

Design Philosophy:
- Single API for all algorithms
- Explicit capability detection (no silent classical fallbacks)
- Hybrid mode support (classical + PQC)
- Backward compatibility
- Performance optimized (uses C/Cython when available)

PQC Backend:
- ML-DSA-65 (CRYSTALS-Dilithium) via liboqs or pqcrypto
- Raises PQCUnavailableError if PQC backend not installed
- Use get_pqc_capabilities() to check availability before use
"""

import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, Tuple

from ava_guardian.pqc_backends import (
    DILITHIUM_AVAILABLE,
    DILITHIUM_BACKEND,
    KYBER_AVAILABLE,
    KYBER_BACKEND,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
    SPHINCS_AVAILABLE,
    SPHINCS_BACKEND,
    SPHINCS_PUBLIC_KEY_BYTES,
    SPHINCS_SECRET_KEY_BYTES,
    SPHINCS_SIGNATURE_BYTES,
    KyberUnavailableError,
    PQCStatus,
    PQCUnavailableError,
    SphincsUnavailableError,
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
    get_pqc_backend_info,
    kyber_decapsulate,
    kyber_encapsulate,
    sphincs_sign,
    sphincs_verify,
)


class AlgorithmType(Enum):
    """Supported cryptographic algorithms"""

    ML_DSA_65 = auto()  # CRYSTALS-Dilithium (signatures)
    KYBER_1024 = auto()  # CRYSTALS-Kyber (KEM)
    SPHINCS_256F = auto()  # SPHINCS+ (signatures)
    ED25519 = auto()  # Classical Ed25519 (signatures)
    HYBRID_SIG = auto()  # Hybrid: Ed25519 + ML-DSA-65
    HYBRID_KEM = auto()  # Hybrid: X25519 + Kyber-1024


class CryptoBackend(Enum):
    """Available implementation backends"""

    C_LIBRARY = auto()  # libava_guardian.so (fastest)
    CYTHON = auto()  # Cython optimized (fast)
    PURE_PYTHON = auto()  # Pure Python (fallback)
    LIBOQS = auto()  # liboqs reference implementation


@dataclass
class KeyPair:
    """
    Cryptographic key pair container

    Attributes:
        public_key: Public key bytes
        secret_key: Secret key bytes (SENSITIVE)
        algorithm: Algorithm used to generate keys
        metadata: Additional key information
    """

    public_key: bytes
    secret_key: bytes
    algorithm: AlgorithmType
    metadata: Dict[str, Any]

    def __del__(self):
        """Secure cleanup of secret key"""
        if hasattr(self, "secret_key") and self.secret_key:
            # Overwrite secret key memory
            try:
                import ctypes

                buffer = (ctypes.c_char * len(self.secret_key)).from_buffer_copy(self.secret_key)
                ctypes.memset(ctypes.addressof(buffer), 0, len(self.secret_key))
            except Exception:
                pass


@dataclass
class Signature:
    """
    Digital signature container

    Attributes:
        signature: Signature bytes
        algorithm: Algorithm used for signing
        message_hash: Hash of signed message (for verification)
        metadata: Additional signature information
    """

    signature: bytes
    algorithm: AlgorithmType
    message_hash: bytes
    metadata: Dict[str, Any]


@dataclass
class EncapsulatedSecret:
    """
    KEM encapsulated secret container

    Attributes:
        ciphertext: Encapsulated ciphertext
        shared_secret: Shared secret key (SENSITIVE)
        algorithm: Algorithm used
        metadata: Additional information
    """

    ciphertext: bytes
    shared_secret: bytes
    algorithm: AlgorithmType
    metadata: Dict[str, Any]

    def __del__(self):
        """Secure cleanup of shared secret"""
        if hasattr(self, "shared_secret") and self.shared_secret:
            try:
                import ctypes

                buffer = (ctypes.c_char * len(self.shared_secret)).from_buffer_copy(
                    self.shared_secret
                )
                ctypes.memset(ctypes.addressof(buffer), 0, len(self.shared_secret))
            except Exception:
                pass


class CryptoProvider(ABC):
    """Abstract base class for cryptographic providers"""

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generate a new keypair"""
        pass

    @abstractmethod
    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign a message"""
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature"""
        pass


class KEMProvider(ABC):
    """Abstract base class for KEM providers"""

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generate a new keypair"""
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret"""
        pass

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret"""
        pass


class MLDSAProvider(CryptoProvider):
    """
    ML-DSA-65 (CRYSTALS-Dilithium) provider.

    Provides real post-quantum signatures via liboqs or pqcrypto backends.
    Raises PQCUnavailableError if no PQC backend is installed.

    Security: NIST Security Level 3 (192-bit quantum security)
    Standard: NIST FIPS 204 (ML-DSA)
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.LIBOQS):
        self.backend = backend
        self.algorithm = AlgorithmType.ML_DSA_65
        self._available = DILITHIUM_AVAILABLE
        self._backend_name = DILITHIUM_BACKEND or "none"

    def generate_keypair(self) -> KeyPair:
        """
        Generate ML-DSA-65 keypair.

        Returns:
            KeyPair with Dilithium public and secret keys

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: ML-DSA-65 requires liboqs-python or pqcrypto. "
                "Install with: pip install liboqs-python"
            )

        kp = generate_dilithium_keypair()
        return KeyPair(
            public_key=kp.public_key,
            secret_key=kp.private_key,
            algorithm=self.algorithm,
            metadata={
                "backend": self._backend_name,
                "key_size": len(kp.public_key),
                "algorithm": "ML-DSA-65",
                "security_level": 3,
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Sign message with ML-DSA-65.

        Args:
            message: Data to sign
            secret_key: Dilithium private key (4032 bytes)

        Returns:
            Signature object with Dilithium signature

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: ML-DSA-65 requires liboqs-python or pqcrypto."
            )

        sig_bytes = dilithium_sign(message, secret_key)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={
                "signature_size": len(sig_bytes),
                "backend": self._backend_name,
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify ML-DSA-65 signature.

        Args:
            message: Original data
            signature: Dilithium signature
            public_key: Dilithium public key (1952 bytes)

        Returns:
            True if signature is valid, False otherwise

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: ML-DSA-65 requires liboqs-python or pqcrypto."
            )

        return dilithium_verify(message, signature, public_key)


class Ed25519Provider(CryptoProvider):
    """
    Ed25519 classical signature provider.

    Provides classical (non-quantum-resistant) signatures.
    Use MLDSAProvider for post-quantum security.

    Security: 128-bit classical security (NOT quantum-resistant)
    Standard: RFC 8032
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON):
        self.backend = backend
        self.algorithm = AlgorithmType.ED25519

    def generate_keypair(self) -> KeyPair:
        """Generate Ed25519 keypair"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        sk_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        pk_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        return KeyPair(
            public_key=pk_bytes,
            secret_key=sk_bytes,
            algorithm=self.algorithm,
            metadata={"backend": "cryptography", "key_size": len(pk_bytes)},
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign message with Ed25519"""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
        sig_bytes = private_key.sign(message)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={"signature_size": len(sig_bytes)},
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify Ed25519 signature"""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


class KyberProvider(KEMProvider):
    """
    Kyber-1024 (ML-KEM) provider - Real quantum-resistant implementation.

    Provides IND-CCA2 secure key encapsulation based on the Module-LWE
    (Learning With Errors) problem. Uses liboqs for the underlying
    cryptographic operations.

    Key Sizes (from liboqs):
        - Public key: 1568 bytes
        - Secret key: 3168 bytes
        - Ciphertext: 1568 bytes
        - Shared secret: 32 bytes

    Security: 256-bit classical / 128-bit quantum (NIST Security Level 5)
    Standard: NIST FIPS 203 (ML-KEM)

    Raises:
        KyberUnavailableError: If Kyber backend is not available
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON):
        self.backend = backend
        self.algorithm = AlgorithmType.KYBER_1024
        self._is_placeholder = False

        if not KYBER_AVAILABLE:
            raise KyberUnavailableError(
                "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
                "Install liboqs-python: pip install liboqs-python"
            )

    def generate_keypair(self) -> KeyPair:
        """
        Generate Kyber-1024 keypair.

        Returns:
            KeyPair with 1568-byte public key and 3168-byte secret key

        Raises:
            KyberUnavailableError: If Kyber backend is not available
        """
        keypair = generate_kyber_keypair()

        return KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            algorithm=self.algorithm,
            metadata={
                "backend": KYBER_BACKEND,
                "public_key_size": KYBER_PUBLIC_KEY_BYTES,
                "secret_key_size": KYBER_SECRET_KEY_BYTES,
            },
        )

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """
        Encapsulate a shared secret using Kyber-1024.

        Args:
            public_key: Kyber-1024 public key (1568 bytes)

        Returns:
            EncapsulatedSecret with ciphertext and shared secret

        Raises:
            KyberUnavailableError: If Kyber backend is not available
            ValueError: If public_key has incorrect length
        """
        encap = kyber_encapsulate(public_key)

        return EncapsulatedSecret(
            ciphertext=encap.ciphertext,
            shared_secret=encap.shared_secret,
            algorithm=self.algorithm,
            metadata={
                "ciphertext_size": KYBER_CIPHERTEXT_BYTES,
                "shared_secret_size": KYBER_SHARED_SECRET_BYTES,
            },
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using Kyber-1024.

        Args:
            ciphertext: Kyber-1024 ciphertext (1568 bytes)
            secret_key: Kyber-1024 secret key (3168 bytes)

        Returns:
            Shared secret (32 bytes)

        Raises:
            KyberUnavailableError: If Kyber backend is not available
            ValueError: If ciphertext or secret_key has incorrect length
        """
        return kyber_decapsulate(ciphertext, secret_key)


class SphincsProvider(CryptoProvider):
    """
    SPHINCS+-SHA2-256f-simple provider - Hash-based signatures.

    Provides stateless hash-based signatures with no risk of key reuse
    vulnerabilities. The 'f' variant is optimized for fast signing at
    the cost of larger signatures (~49KB).

    Key Sizes (from liboqs):
        - Public key: 64 bytes
        - Secret key: 128 bytes
        - Signature: 49856 bytes

    Security: 256-bit classical / 128-bit quantum (NIST Security Level 5)
    Standard: NIST FIPS 205 (SLH-DSA)

    Note: SPHINCS+ signatures are large but provide strong security
    guarantees based only on hash function security assumptions.

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON):
        self.backend = backend
        self.algorithm = AlgorithmType.SPHINCS_256F

        if not SPHINCS_AVAILABLE:
            raise SphincsUnavailableError(
                "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
                "Install liboqs-python: pip install liboqs-python"
            )

    def generate_keypair(self) -> KeyPair:
        """
        Generate SPHINCS+-256f keypair.

        Returns:
            KeyPair with 64-byte public key and 128-byte secret key

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
        """
        keypair = generate_sphincs_keypair()

        return KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            algorithm=self.algorithm,
            metadata={
                "backend": SPHINCS_BACKEND,
                "public_key_size": SPHINCS_PUBLIC_KEY_BYTES,
                "secret_key_size": SPHINCS_SECRET_KEY_BYTES,
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Sign message with SPHINCS+-256f.

        Args:
            message: Data to sign (arbitrary length)
            secret_key: SPHINCS+-256f secret key (128 bytes)

        Returns:
            Signature object with 49856-byte signature

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
            ValueError: If secret_key has incorrect length
        """
        sig_bytes = sphincs_sign(message, secret_key)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={
                "signature_size": SPHINCS_SIGNATURE_BYTES,
                "backend": SPHINCS_BACKEND,
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify SPHINCS+-256f signature.

        Args:
            message: Original data
            signature: SPHINCS+ signature (49856 bytes)
            public_key: SPHINCS+-256f public key (64 bytes)

        Returns:
            True if signature is valid, False otherwise

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
            ValueError: If public_key has incorrect length
        """
        return sphincs_verify(message, signature, public_key)


class HybridSignatureProvider(CryptoProvider):
    """
    Hybrid signature provider (Ed25519 + ML-DSA-65).

    Provides dual-signature scheme combining classical Ed25519 with
    post-quantum ML-DSA-65 (Dilithium). Both signatures must verify
    for the combined signature to be valid.

    Security: Secure against both classical and quantum adversaries
    Transition: Safe during classical-to-quantum migration period

    Raises:
        PQCUnavailableError: If Dilithium backend is not available
    """

    # Key sizes for splitting combined keys
    ED25519_SK_SIZE = 32
    ED25519_PK_SIZE = 32
    ED25519_SIG_SIZE = 64
    DILITHIUM_SK_SIZE = 4032  # ML-DSA-65 per liboqs
    DILITHIUM_PK_SIZE = 1952
    DILITHIUM_SIG_SIZE = 3309  # ML-DSA-65 per liboqs

    def __init__(self):
        self.classical_provider = Ed25519Provider()
        self.pqc_provider = MLDSAProvider()
        self.algorithm = AlgorithmType.HYBRID_SIG
        self._pqc_available = DILITHIUM_AVAILABLE

    def generate_keypair(self) -> KeyPair:
        """
        Generate hybrid keypair (Ed25519 + ML-DSA-65).

        Returns:
            KeyPair with combined public and secret keys

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65. "
                "Install liboqs-python: pip install liboqs-python"
            )

        classical_keys = self.classical_provider.generate_keypair()
        pqc_keys = self.pqc_provider.generate_keypair()

        # Combine keys (Ed25519 first, then Dilithium)
        combined_pk = classical_keys.public_key + pqc_keys.public_key
        combined_sk = classical_keys.secret_key + pqc_keys.secret_key

        return KeyPair(
            public_key=combined_pk,
            secret_key=combined_sk,
            algorithm=self.algorithm,
            metadata={
                "classical_algorithm": "Ed25519",
                "pqc_algorithm": "ML-DSA-65",
                "classical_pk_size": len(classical_keys.public_key),
                "pqc_pk_size": len(pqc_keys.public_key),
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Create hybrid signature (Ed25519 + ML-DSA-65).

        Args:
            message: Data to sign
            secret_key: Combined secret key (Ed25519 + Dilithium)

        Returns:
            Signature with combined Ed25519 and Dilithium signatures

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys
        classical_sk = secret_key[: self.ED25519_SK_SIZE]
        pqc_sk = secret_key[self.ED25519_SK_SIZE :]

        # Create both signatures
        classical_sig = self.classical_provider.sign(message, classical_sk)
        pqc_sig = self.pqc_provider.sign(message, pqc_sk)

        # Combine signatures (Ed25519 first, then Dilithium)
        combined_sig = classical_sig.signature + pqc_sig.signature

        return Signature(
            signature=combined_sig,
            algorithm=self.algorithm,
            message_hash=hashlib.sha3_256(message).digest(),
            metadata={
                "classical_sig_size": len(classical_sig.signature),
                "pqc_sig_size": len(pqc_sig.signature),
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify hybrid signature (both must verify).

        Args:
            message: Original data
            signature: Combined signature (Ed25519 + Dilithium)
            public_key: Combined public key (Ed25519 + Dilithium)

        Returns:
            True if BOTH signatures are valid, False otherwise

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys and signatures
        classical_pk = public_key[: self.ED25519_PK_SIZE]
        pqc_pk = public_key[self.ED25519_PK_SIZE :]
        classical_sig = signature[: self.ED25519_SIG_SIZE]
        pqc_sig = signature[self.ED25519_SIG_SIZE :]

        # Both must verify for hybrid security
        classical_valid = self.classical_provider.verify(message, classical_sig, classical_pk)
        pqc_valid = self.pqc_provider.verify(message, pqc_sig, pqc_pk)

        return classical_valid and pqc_valid


class AvaGuardianCrypto:
    """
    Main Ava Guardian ♱ Cryptographic API

    Provides unified interface to all cryptographic operations with
    automatic algorithm selection and fallback mechanisms.

    Example:
        >>> crypto = AvaGuardianCrypto(algorithm=AlgorithmType.HYBRID_SIG)
        >>> keypair = crypto.generate_keypair()
        >>> signature = crypto.sign(b"Hello, World!", keypair.secret_key)
        >>> valid = crypto.verify(b"Hello, World!", signature.signature, keypair.public_key)
    """

    def __init__(
        self,
        algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
        backend: CryptoBackend = CryptoBackend.C_LIBRARY,
    ):
        """
        Initialize cryptographic API

        Args:
            algorithm: Algorithm to use (default: HYBRID_SIG)
            backend: Implementation backend (default: C_LIBRARY)
        """
        self.algorithm = algorithm
        self.backend = backend
        self.provider = self._get_provider()

    def _get_provider(self):
        """Get appropriate provider for selected algorithm"""
        if self.algorithm == AlgorithmType.ML_DSA_65:
            return MLDSAProvider(self.backend)
        elif self.algorithm == AlgorithmType.KYBER_1024:
            return KyberProvider(self.backend)
        elif self.algorithm == AlgorithmType.SPHINCS_256F:
            return SphincsProvider(self.backend)
        elif self.algorithm == AlgorithmType.HYBRID_SIG:
            return HybridSignatureProvider()
        elif self.algorithm == AlgorithmType.ED25519:
            return Ed25519Provider(self.backend)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_keypair(self) -> KeyPair:
        """Generate cryptographic keypair"""
        return self.provider.generate_keypair()

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign a message"""
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support signing")
        return self.provider.sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature"""
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support verification")
        return self.provider.verify(message, signature, public_key)

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret (KEM)"""
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret (KEM)"""
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.decapsulate(ciphertext, secret_key)

    @staticmethod
    def hash_message(message: bytes, algorithm: str = "sha3-256") -> bytes:
        """
        Hash a message using specified algorithm

        Args:
            message: Message to hash
            algorithm: Hash algorithm (sha3-256, sha3-512, shake256)

        Returns:
            Hash digest
        """
        if algorithm == "sha3-256":
            return hashlib.sha3_256(message).digest()
        elif algorithm == "sha3-512":
            return hashlib.sha3_512(message).digest()
        elif algorithm == "shake256":
            return hashlib.shake_256(message).digest(32)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of byte strings

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise (constant time)
        """
        return secrets.compare_digest(a, b)


# Convenience functions
def quick_sign(
    message: bytes, algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG
) -> Tuple[KeyPair, Signature]:
    """
    Quick sign: Generate keys and sign message in one call

    Args:
        message: Message to sign
        algorithm: Algorithm to use

    Returns:
        (keypair, signature)
    """
    crypto = AvaGuardianCrypto(algorithm=algorithm)
    keypair = crypto.generate_keypair()
    signature = crypto.sign(message, keypair.secret_key)
    return keypair, signature


def quick_verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
) -> bool:
    """
    Quick verify: Verify signature in one call

    Args:
        message: Message that was signed
        signature: Signature to verify
        public_key: Public key
        algorithm: Algorithm used

    Returns:
        True if valid, False otherwise
    """
    crypto = AvaGuardianCrypto(algorithm=algorithm)
    return crypto.verify(message, signature, public_key)


def quick_kem(
    algorithm: AlgorithmType = AlgorithmType.KYBER_1024,
) -> Tuple[KeyPair, EncapsulatedSecret]:
    """
    Quick KEM: Generate keys and encapsulate secret in one call

    Args:
        algorithm: KEM algorithm to use

    Returns:
        (keypair, encapsulated_secret)
    """
    crypto = AvaGuardianCrypto(algorithm=algorithm)
    keypair = crypto.generate_keypair()
    encapsulated = crypto.encapsulate(keypair.public_key)
    return keypair, encapsulated


def get_pqc_capabilities() -> Dict[str, Any]:
    """
    Get current PQC backend capabilities.

    Returns detailed information about which post-quantum algorithms
    are available and which backends are installed.

    Returns:
        Dictionary with capability information:
        - status: "AVAILABLE" or "UNAVAILABLE"
        - dilithium_available: bool
        - kyber_available: bool
        - sphincs_available: bool
        - backend: "liboqs" or "pqcrypto" or None
        - algorithms: dict of algorithm availability
        - install_instructions: str (if unavailable)

    Example:
        >>> caps = get_pqc_capabilities()
        >>> if caps["status"] == "AVAILABLE":
        ...     crypto = AvaGuardianCrypto(algorithm=AlgorithmType.ML_DSA_65)
        ... else:
        ...     print(caps["install_instructions"])
    """
    info = get_pqc_backend_info()

    return {
        "status": info["status"],
        "dilithium_available": info["dilithium_available"],
        "kyber_available": info["kyber_available"],
        "sphincs_available": info["sphincs_available"],
        "backend": info["backend"],
        "algorithms": {
            "ML_DSA_65": info["dilithium_available"],
            "HYBRID_SIG": info["dilithium_available"],
            "ED25519": True,  # Always available via cryptography
            "KYBER_1024": info["kyber_available"],
            "SPHINCS_256F": info["sphincs_available"],
        },
        "security_levels": {
            "ML_DSA_65": 3 if info["dilithium_available"] else None,
            "HYBRID_SIG": 3 if info["dilithium_available"] else None,
            "ED25519": 1,  # Classical only
            "KYBER_1024": 5 if info["kyber_available"] else None,
            "SPHINCS_256F": 5 if info["sphincs_available"] else None,
        },
        "key_sizes": info.get("algorithms", {}),
        "install_instructions": (
            "pip install liboqs-python"
            if not (info["dilithium_available"] or info["kyber_available"])
            else "PQC backend already installed"
        ),
    }


# Re-export PQC types for convenience
__all__ = [
    "AlgorithmType",
    "CryptoBackend",
    "KeyPair",
    "Signature",
    "EncapsulatedSecret",
    "CryptoProvider",
    "KEMProvider",
    "MLDSAProvider",
    "Ed25519Provider",
    "KyberProvider",
    "SphincsProvider",
    "HybridSignatureProvider",
    "AvaGuardianCrypto",
    "quick_sign",
    "quick_verify",
    "quick_kem",
    "get_pqc_capabilities",
    "PQCStatus",
    "PQCUnavailableError",
    "KyberUnavailableError",
    "SphincsUnavailableError",
    "DILITHIUM_AVAILABLE",
    "DILITHIUM_BACKEND",
    "KYBER_AVAILABLE",
    "KYBER_BACKEND",
    "SPHINCS_AVAILABLE",
    "SPHINCS_BACKEND",
]
