#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Fuzzing tests using Hypothesis for property-based testing.

These tests verify that core cryptographic functions maintain their
invariants under random inputs, helping detect edge cases and
potential security issues.
"""

import secrets

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from dna_guardian_secure import (
    canonical_hash_dna,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    hmac_authenticate,
    hmac_verify,
    length_prefixed_encode,
    secure_wipe,
)


class TestLengthPrefixFuzzing:
    """Fuzz tests for length-prefixed encoding."""

    @given(st.lists(st.text(max_size=500), min_size=1, max_size=20))
    @settings(max_examples=500, deadline=None)
    def test_encoding_deterministic(self, fields):
        """Same input always produces same output (determinism)."""
        e1 = length_prefixed_encode(*fields)
        e2 = length_prefixed_encode(*fields)
        assert e1 == e2, "Encoding must be deterministic"

    @given(
        st.lists(st.text(max_size=100), min_size=1, max_size=10),
        st.lists(st.text(max_size=100), min_size=1, max_size=10),
    )
    @settings(max_examples=500, deadline=None)
    def test_no_collisions(self, fields1, fields2):
        """Different inputs produce different outputs (collision resistance)."""
        assume(fields1 != fields2)
        e1 = length_prefixed_encode(*fields1)
        e2 = length_prefixed_encode(*fields2)
        assert e1 != e2, f"Collision detected: {fields1} vs {fields2}"

    @given(st.lists(st.binary(max_size=100), min_size=1, max_size=10))
    @settings(max_examples=200, deadline=None)
    def test_binary_fields_roundtrip(self, fields):
        """Binary fields encode without error."""
        # Convert binary to strings for encoding
        str_fields = [f.hex() for f in fields]
        result = length_prefixed_encode(*str_fields)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestCanonicalHashFuzzing:
    """Fuzz tests for canonical DNA hashing."""

    @given(
        st.text(min_size=1, max_size=1000, alphabet="ACGT"),
        st.lists(
            st.tuples(
                st.floats(min_value=0.01, max_value=100, allow_nan=False, allow_infinity=False),
                st.floats(min_value=0.01, max_value=100, allow_nan=False, allow_infinity=False),
            ),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(max_examples=300, deadline=None)
    def test_hash_deterministic(self, dna, params):
        """Hash is deterministic for same inputs."""
        h1 = canonical_hash_dna(dna, params)
        h2 = canonical_hash_dna(dna, params)
        assert h1 == h2, "Hash must be deterministic"
        assert len(h1) == 32, "SHA3-256 produces 32 bytes"

    @given(
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
    )
    @settings(max_examples=200, deadline=None)
    def test_different_dna_different_hash(self, dna1, dna2):
        """Different DNA sequences produce different hashes."""
        assume(dna1 != dna2)
        params = [(1.0, 1.0)]
        h1 = canonical_hash_dna(dna1, params)
        h2 = canonical_hash_dna(dna2, params)
        assert h1 != h2, f"Hash collision: {dna1} vs {dna2}"


class TestHMACFuzzing:
    """Fuzz tests for HMAC authentication."""

    @given(st.binary(max_size=10000))
    @settings(max_examples=300, deadline=None)
    def test_hmac_roundtrip(self, message):
        """HMAC verify accepts valid tags."""
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(message, key)
        assert hmac_verify(message, tag, key), "Valid HMAC must verify"

    @given(st.binary(max_size=1000))
    @settings(max_examples=200, deadline=None)
    def test_modified_tag_fails(self, message):
        """Modified tags fail verification (integrity)."""
        key = secrets.token_bytes(32)
        tag = bytearray(hmac_authenticate(message, key))
        tag[0] ^= 0xFF  # Flip all bits in first byte
        assert not hmac_verify(message, bytes(tag), key), "Modified tag must fail"

    @given(st.binary(max_size=1000))
    @settings(max_examples=200, deadline=None)
    def test_wrong_key_fails(self, message):
        """Wrong key fails verification (authentication)."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assume(key1 != key2)
        tag = hmac_authenticate(message, key1)
        assert not hmac_verify(message, tag, key2), "Wrong key must fail"

    @given(st.binary(max_size=1000), st.binary(max_size=1000))
    @settings(max_examples=200, deadline=None)
    def test_modified_message_fails(self, message1, message2):
        """Modified message fails verification."""
        assume(message1 != message2)
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(message1, key)
        assert not hmac_verify(message2, tag, key), "Modified message must fail"


class TestEd25519Fuzzing:
    """Fuzz tests for Ed25519 signatures."""

    @given(st.binary(max_size=10000))
    @settings(max_examples=100, deadline=None)
    def test_sign_verify_roundtrip(self, message):
        """Signatures verify correctly."""
        kp = generate_ed25519_keypair()
        sig = ed25519_sign(message, kp.private_key)
        assert ed25519_verify(message, sig, kp.public_key), "Valid signature must verify"

    @given(st.binary(max_size=1000))
    @settings(max_examples=50, deadline=None)
    def test_modified_signature_fails(self, message):
        """Modified signatures fail verification."""
        kp = generate_ed25519_keypair()
        sig = bytearray(ed25519_sign(message, kp.private_key))
        sig[0] ^= 0xFF
        assert not ed25519_verify(message, bytes(sig), kp.public_key), "Modified sig must fail"

    @given(st.binary(max_size=1000))
    @settings(max_examples=50, deadline=None)
    def test_wrong_key_fails(self, message):
        """Wrong public key fails verification."""
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        sig = ed25519_sign(message, kp1.private_key)
        assert not ed25519_verify(message, sig, kp2.public_key), "Wrong key must fail"


class TestSecureWipeFuzzing:
    """Fuzz tests for secure memory wiping."""

    @given(st.binary(min_size=1, max_size=10000))
    @settings(max_examples=200, deadline=None)
    def test_wipe_zeros_all_bytes(self, data):
        """secure_wipe zeros all bytes in bytearray."""
        ba = bytearray(data)
        assume(any(b != 0 for b in ba))  # Ensure not already zeroed

        secure_wipe(ba)

        assert all(b == 0 for b in ba), "All bytes must be zeroed"
        assert len(ba) == len(data), "Length must be preserved"
