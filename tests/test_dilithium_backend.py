#!/usr/bin/env python3
"""
Test script to verify Dilithium backend functionality.

Tests both liboqs-python and pqcrypto backends to ensure
quantum-resistant signatures are working correctly.
"""

import sys


def test_liboqs_backend():
    """Test liboqs-python backend."""
    print("Testing liboqs-python backend...")
    try:
        import oqs

        print("  ✓ liboqs-python imported successfully")

        # Test Dilithium3 key generation
        sig = oqs.Signature("Dilithium3")
        print("  ✓ Dilithium3 signature object created")

        # Generate keypair
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        print(
            f"  ✓ Keypair generated: pk={len(public_key)} bytes, sk={len(private_key)} bytes"
        )

        # Test signing
        message = b"Test message for Dilithium signature"
        signature = sig.sign(message)
        print(f"  ✓ Message signed: signature={len(signature)} bytes")

        # Test verification
        is_valid = sig.verify(message, signature, public_key)
        if is_valid:
            print("  ✓ Signature verified successfully")
        else:
            print("  ✗ Signature verification failed")
            return False

        print("✓ liboqs-python backend: PASSED\n")
        return True

    except ImportError as e:
        print(f"  ✗ ImportError: {e}")
        print("  Install with: pip install liboqs-python")
        return False
    except RuntimeError as e:
        print(f"  ✗ RuntimeError: {e}")
        print("  The liboqs shared library may be missing")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


def test_pqcrypto_backend():
    """Test pqcrypto backend (fallback)."""
    print("Testing pqcrypto backend...")
    try:
        from pqcrypto.sign import dilithium3

        print("  ✓ pqcrypto.sign.dilithium3 imported successfully")

        # Generate keypair
        public_key, private_key = dilithium3.generate_keypair()
        print(
            f"  ✓ Keypair generated: pk={len(public_key)} bytes, sk={len(private_key)} bytes"
        )

        # Test signing
        message = b"Test message for Dilithium signature"
        signature = dilithium3.sign(message, private_key)
        print(f"  ✓ Message signed: signature={len(signature)} bytes")

        # Test verification
        dilithium3.verify(message, signature, public_key)
        print("  ✓ Signature verified successfully")

        print("✓ pqcrypto backend: PASSED\n")
        return True

    except ImportError as e:
        print(f"  ✗ ImportError: {e}")
        print("  Install with: pip install pqcrypto")
        return False
    except Exception as e:
        print(f"  ✗ Verification or other error: {e}")
        return False


def main():
    """Run all backend tests."""
    print("=" * 70)
    print("Dilithium Backend Test Suite")
    print("=" * 70)
    print()

    liboqs_ok = test_liboqs_backend()
    pqcrypto_ok = test_pqcrypto_backend()

    print("=" * 70)
    print("Test Results Summary:")
    print(f"  liboqs-python: {'PASSED' if liboqs_ok else 'FAILED'}")
    print(f"  pqcrypto:      {'PASSED' if pqcrypto_ok else 'FAILED'}")
    print("=" * 70)

    # At least one backend should work
    if liboqs_ok or pqcrypto_ok:
        print("\n✓ At least one Dilithium backend is available")
        return 0
    else:
        print("\n✗ No Dilithium backend available!")
        print("\nInstall one of the following:")
        print("  pip install liboqs-python  (recommended)")
        print("  pip install pqcrypto       (alternative)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
