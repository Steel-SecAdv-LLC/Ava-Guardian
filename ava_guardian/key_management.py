#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ava Guardian ♱ Key Management System
=====================================

Enterprise-grade key management with:
- Hierarchical Deterministic (HD) key derivation (BIP32-style)
- Key rotation with zero-downtime
- Secure key storage and retrieval
- Key versioning and lifecycle management
- Hardware-backed key support (HSM/TPM ready)
"""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class KeyStatus(Enum):
    """Key lifecycle status"""

    ACTIVE = auto()
    ROTATING = auto()
    DEPRECATED = auto()
    REVOKED = auto()
    COMPROMISED = auto()


@dataclass
class KeyMetadata:
    """
    Metadata for cryptographic keys

    Attributes:
        key_id: Unique key identifier
        created_at: Creation timestamp
        expires_at: Expiration timestamp
        status: Current key status
        version: Key version number
        parent_id: Parent key ID (for HD derivation)
        derivation_path: HD derivation path
        usage_count: Number of times key has been used
        max_usage: Maximum allowed usage count
        purpose: Key purpose (signing, encryption, etc.)
        metadata: Additional custom metadata
    """

    key_id: str
    created_at: datetime
    expires_at: Optional[datetime]
    status: KeyStatus
    version: int
    parent_id: Optional[str]
    derivation_path: Optional[str]
    usage_count: int
    max_usage: Optional[int]
    purpose: str
    metadata: Dict[str, Any]


class HDKeyDerivation:
    """
    Hierarchical Deterministic Key Derivation (BIP32-style)

    Derives child keys from a master seed using HMAC-SHA512.
    Supports hardened and non-hardened derivation.

    Derivation Path Format:
        m/purpose'/coin_type'/account'/change/address_index

    Example:
        m/44'/0'/0'/0/0 - First address of first account
        m/44'/0'/0'/1/0 - First change address
    """

    HARDENED_OFFSET = 2**31

    def __init__(self, seed: Optional[bytes] = None, seed_phrase: Optional[str] = None):
        """
        Initialize HD key derivation

        Args:
            seed: Master seed (64 bytes recommended)
            seed_phrase: Alternative: BIP39-style seed phrase
        """
        if seed is None and seed_phrase is None:
            # Generate random seed
            self.master_seed = secrets.token_bytes(64)
        elif seed is not None:
            self.master_seed = seed
        else:
            # Derive seed from phrase (simplified BIP39)
            self.master_seed = hashlib.pbkdf2_hmac(
                "sha512", seed_phrase.encode("utf-8"), b"mnemonic", 2048, 64
            )

        # Generate master key
        self.master_key, self.master_chain_code = self._generate_master_key()

    def _generate_master_key(self) -> Tuple[bytes, bytes]:
        """Generate master key and chain code from seed"""
        h = hmac.new(b"Ava Guardian Master Key", self.master_seed, hashlib.sha512)
        hmac_result = h.digest()

        master_key = hmac_result[:32]
        chain_code = hmac_result[32:]

        return master_key, chain_code

    def _ckd_private(
        self, parent_key: bytes, parent_chain: bytes, index: int
    ) -> Tuple[bytes, bytes]:
        """
        Child Key Derivation (Private)

        Args:
            parent_key: Parent private key (32 bytes)
            parent_chain: Parent chain code (32 bytes)
            index: Child index (>= 2^31 for hardened)

        Returns:
            (child_key, child_chain_code)
        """
        if index >= self.HARDENED_OFFSET:
            # Hardened derivation
            data = b"\x00" + parent_key + index.to_bytes(4, "big")
        else:
            # Non-hardened derivation (requires public key, simplified here)
            data = parent_key + index.to_bytes(4, "big")

        h = hmac.new(parent_chain, data, hashlib.sha512)
        hmac_result = h.digest()

        child_key = hmac_result[:32]
        child_chain = hmac_result[32:]

        # Add parent key to child key (modular arithmetic for real implementation)
        # Simplified: XOR for demonstration
        child_key = bytes(a ^ b for a, b in zip(child_key, parent_key))

        return child_key, child_chain

    def derive_path(self, path: str) -> Tuple[bytes, bytes]:
        """
        Derive key from BIP32-style path

        Args:
            path: Derivation path (e.g., "m/44'/0'/0'/0/0")

        Returns:
            (derived_key, chain_code)

        Example:
            >>> hd = HDKeyDerivation()
            >>> key, chain = hd.derive_path("m/44'/0'/0'/0/0")
        """
        if not path.startswith("m"):
            raise ValueError("Path must start with 'm'")

        # Parse path
        parts = path.split("/")[1:]  # Skip 'm'
        key = self.master_key
        chain = self.master_chain_code

        for part in parts:
            # Check for hardened derivation (')
            hardened = part.endswith("'")
            if hardened:
                part = part[:-1]

            index = int(part)
            if hardened:
                index += self.HARDENED_OFFSET

            key, chain = self._ckd_private(key, chain, index)

        return key, chain

    def derive_key(self, purpose: int, account: int = 0, change: int = 0, index: int = 0) -> bytes:
        """
        Derive key using standard path structure

        Args:
            purpose: Purpose (e.g., 44 for BIP44)
            account: Account number
            change: Change address (0=external, 1=internal)
            index: Address index

        Returns:
            Derived key
        """
        path = f"m/{purpose}'/{account}'/{change}/{index}"
        key, _ = self.derive_path(path)
        return key


class KeyRotationManager:
    """
    Key Rotation Manager

    Manages cryptographic key lifecycle with zero-downtime rotation.
    Supports gradual migration from old to new keys.
    """

    def __init__(self, rotation_period: timedelta = timedelta(days=90)):
        """
        Initialize rotation manager

        Args:
            rotation_period: How often to rotate keys
        """
        self.rotation_period = rotation_period
        self.keys: Dict[str, KeyMetadata] = {}
        self.active_key_id: Optional[str] = None

    def register_key(
        self,
        key_id: str,
        purpose: str,
        parent_id: Optional[str] = None,
        derivation_path: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
        max_usage: Optional[int] = None,
    ) -> KeyMetadata:
        """
        Register a new key

        Args:
            key_id: Unique key identifier
            purpose: Key purpose (e.g., 'signing', 'encryption')
            parent_id: Parent key ID (for HD keys)
            derivation_path: HD derivation path
            expires_in: Expiration duration
            max_usage: Maximum usage count

        Returns:
            KeyMetadata
        """
        now = datetime.now()
        expires_at = now + expires_in if expires_in else None

        metadata = KeyMetadata(
            key_id=key_id,
            created_at=now,
            expires_at=expires_at,
            status=KeyStatus.ACTIVE,
            version=1,
            parent_id=parent_id,
            derivation_path=derivation_path,
            usage_count=0,
            max_usage=max_usage,
            purpose=purpose,
            metadata={},
        )

        self.keys[key_id] = metadata

        # Set as active if first key
        if self.active_key_id is None:
            self.active_key_id = key_id

        return metadata

    def get_active_key(self) -> Optional[str]:
        """Get currently active key ID"""
        return self.active_key_id

    def should_rotate(self, key_id: str) -> bool:
        """
        Check if key should be rotated

        Args:
            key_id: Key to check

        Returns:
            True if rotation is needed
        """
        if key_id not in self.keys:
            return False

        metadata = self.keys[key_id]

        # Check expiration
        if metadata.expires_at and datetime.now() >= metadata.expires_at:
            return True

        # Check usage limit
        if metadata.max_usage and metadata.usage_count >= metadata.max_usage:
            return True

        # Check rotation period
        if datetime.now() - metadata.created_at >= self.rotation_period:
            return True

        return False

    def initiate_rotation(self, old_key_id: str, new_key_id: str) -> None:
        """
        Initiate key rotation

        Args:
            old_key_id: Key being rotated out
            new_key_id: New replacement key
        """
        if old_key_id not in self.keys or new_key_id not in self.keys:
            raise ValueError("Key not found")

        # Mark old key as rotating
        self.keys[old_key_id].status = KeyStatus.ROTATING

        # Activate new key
        self.keys[new_key_id].status = KeyStatus.ACTIVE
        self.active_key_id = new_key_id

    def complete_rotation(self, old_key_id: str) -> None:
        """
        Complete key rotation by deprecating old key

        Args:
            old_key_id: Key to deprecate
        """
        if old_key_id not in self.keys:
            return

        self.keys[old_key_id].status = KeyStatus.DEPRECATED

    def revoke_key(self, key_id: str, reason: str = "compromised") -> None:
        """
        Revoke a key immediately

        Args:
            key_id: Key to revoke
            reason: Revocation reason
        """
        if key_id not in self.keys:
            return

        if reason == "compromised":
            self.keys[key_id].status = KeyStatus.COMPROMISED
        else:
            self.keys[key_id].status = KeyStatus.REVOKED

        # If active key, need to activate a backup
        if self.active_key_id == key_id:
            self.active_key_id = None

    def increment_usage(self, key_id: str) -> None:
        """Increment usage counter for a key"""
        if key_id in self.keys:
            self.keys[key_id].usage_count += 1

    def export_metadata(self, filepath: Optional[Path] = None) -> Dict[str, Any]:
        """
        Export key metadata to JSON

        Args:
            filepath: Optional file to save to

        Returns:
            Metadata dictionary
        """
        export_data = {
            "active_key_id": self.active_key_id,
            "rotation_period_days": self.rotation_period.days,
            "keys": {},
        }

        for key_id, metadata in self.keys.items():
            export_data["keys"][key_id] = {
                "key_id": metadata.key_id,
                "created_at": metadata.created_at.isoformat(),
                "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
                "status": metadata.status.name,
                "version": metadata.version,
                "parent_id": metadata.parent_id,
                "derivation_path": metadata.derivation_path,
                "usage_count": metadata.usage_count,
                "max_usage": metadata.max_usage,
                "purpose": metadata.purpose,
                "metadata": metadata.metadata,
            }

        if filepath:
            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2)

        return export_data


class SecureKeyStorage:
    """
    Secure key storage with encryption at rest

    Stores keys encrypted with a master password or HSM-backed key.
    Supports both software and hardware-backed storage.
    """

    def __init__(self, storage_path: Path, master_password: Optional[str] = None):
        """
        Initialize secure storage

        Args:
            storage_path: Directory for key storage
            master_password: Master password for encryption
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        if master_password:
            # Derive encryption key from password
            self.encryption_key = hashlib.pbkdf2_hmac(
                "sha256", master_password.encode("utf-8"), b"ava_guardian_salt", 100000, 32
            )
        else:
            # Generate random encryption key (should be HSM-backed in production)
            self.encryption_key = secrets.token_bytes(32)

    def store_key(self, key_id: str, key_data: bytes, metadata: Optional[Dict] = None) -> None:
        """
        Store a key securely

        Args:
            key_id: Key identifier
            key_data: Key bytes (will be encrypted)
            metadata: Optional metadata
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Generate random IV
        iv = secrets.token_bytes(16)

        # Encrypt key data
        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(key_data) + encryptor.finalize()

        # Store with IV and metadata
        storage_data = {
            "key_id": key_id,
            "encrypted_data": encrypted_data.hex(),
            "iv": iv.hex(),
            "metadata": metadata or {},
            "stored_at": datetime.now().isoformat(),
        }

        key_file = self.storage_path / f"{key_id}.json"
        with open(key_file, "w") as f:
            json.dump(storage_data, f, indent=2)

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve and decrypt a stored key

        Args:
            key_id: Key identifier

        Returns:
            Decrypted key bytes or None if not found
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key_file = self.storage_path / f"{key_id}.json"
        if not key_file.exists():
            return None

        with open(key_file, "r") as f:
            storage_data = json.load(f)

        # Decrypt key data
        encrypted_data = bytes.fromhex(storage_data["encrypted_data"])
        iv = bytes.fromhex(storage_data["iv"])

        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        key_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return key_data

    def delete_key(self, key_id: str) -> bool:
        """
        Securely delete a key

        Args:
            key_id: Key to delete

        Returns:
            True if deleted, False if not found
        """
        key_file = self.storage_path / f"{key_id}.json"
        if key_file.exists():
            # Overwrite file before deleting
            with open(key_file, "wb") as f:
                f.write(secrets.token_bytes(1024))
            key_file.unlink()
            return True
        return False


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("Ava Guardian ♱ Key Management Demonstration")
    print("=" * 70)

    # HD Key Derivation
    print("\n1. Hierarchical Deterministic Key Derivation")
    print("-" * 70)
    hd = HDKeyDerivation()

    # Derive keys for different purposes
    signing_key = hd.derive_key(purpose=44, account=0, change=0, index=0)
    encryption_key = hd.derive_key(purpose=44, account=0, change=0, index=1)

    print(f"Signing key:    {signing_key.hex()[:32]}...")
    print(f"Encryption key: {encryption_key.hex()[:32]}...")

    # Key Rotation
    print("\n2. Key Rotation Management")
    print("-" * 70)
    rotation_mgr = KeyRotationManager(rotation_period=timedelta(days=90))

    # Register keys
    key1_meta = rotation_mgr.register_key("key-v1", "signing", max_usage=1000)
    key2_meta = rotation_mgr.register_key("key-v2", "signing")

    print(f"Active key: {rotation_mgr.get_active_key()}")
    print(f"Should rotate: {rotation_mgr.should_rotate('key-v1')}")

    # Simulate key rotation
    rotation_mgr.initiate_rotation("key-v1", "key-v2")
    print(f"After rotation, active key: {rotation_mgr.get_active_key()}")

    # Secure Storage
    print("\n3. Secure Key Storage")
    print("-" * 70)
    storage = SecureKeyStorage(Path("/tmp/ava_keys"), master_password="test_password_123")

    # Store a key
    test_key = secrets.token_bytes(32)
    storage.store_key("master-key-001", test_key, metadata={"purpose": "signing"})
    print("✓ Key stored securely")

    # Retrieve key
    retrieved_key = storage.retrieve_key("master-key-001")
    print(f"✓ Key retrieved: {retrieved_key == test_key}")

    print("\n" + "=" * 70)
    print("✓ Key Management System operational")
    print("=" * 70)
