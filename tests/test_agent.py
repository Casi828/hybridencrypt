"""
test_agent.py — Policy engine + hybrid engine integration tests.

Run with: python3 -m unittest test_agent -v
"""

from __future__ import annotations

import unittest

from spy.ecc_engine import generate_ecc_keypair, serialize_public_key
from spy.hybrid_engine import decrypt_hybrid, encrypt_hybrid
from spy.policy_engine import select_encryption_method
from spy.rsa_engine import generate_rsa_keypair


class TestAgentPipeline(unittest.TestCase):
    """Test the policy → hybrid encryption path used by agents."""

    CONTEXT = {
        "environment": "mobile",
        "compliance_level": "none",
        "performance_priority": "high",
        "legacy_support_required": False,
        "bandwidth_constraint": "low",
    }

    def test_policy_selects_valid_method(self):
        method = select_encryption_method(self.CONTEXT)
        self.assertIn(method, {"rsa", "ecc"})

    def test_rsa_hybrid_round_trip(self):
        priv, pub = generate_rsa_keypair()
        aad = b"test-agent|rsa"
        pkg = encrypt_hybrid(b"Full Pipeline Test", method="rsa", public_key=pub, associated_data=aad)
        result = decrypt_hybrid(
            method="rsa",
            private_key=priv,
            encrypted_aes_key=pkg.encrypted_aes_key,
            encrypted_message=pkg.encrypted_message,
            associated_data=aad,
        )
        self.assertEqual(result, b"Full Pipeline Test")

    def test_ecc_hybrid_round_trip(self):
        recv_priv, recv_pub = generate_ecc_keypair()
        send_priv, send_pub = generate_ecc_keypair()
        sender_public_bytes = serialize_public_key(send_pub)
        aad = b"test-agent|ecc|" + sender_public_bytes
        pkg = encrypt_hybrid(
            b"Full Pipeline Test", method="ecc",
            public_key=recv_pub, sender_private_key=send_priv, associated_data=aad,
        )
        result = decrypt_hybrid(
            method="ecc",
            private_key=recv_priv,
            encrypted_aes_key=pkg.encrypted_aes_key,
            encrypted_message=pkg.encrypted_message,
            sender_public_key=send_pub,
            associated_data=aad,
        )
        self.assertEqual(result, b"Full Pipeline Test")

    def test_policy_driven_encryption(self):
        """Policy selects method; corresponding crypto path completes round trip."""
        method = select_encryption_method(self.CONTEXT)

        if method == "rsa":
            priv, pub = generate_rsa_keypair()
            aad = b"test-agent|rsa"
            pkg = encrypt_hybrid(b"policy-driven", method=method, public_key=pub, associated_data=aad)
            result = decrypt_hybrid("rsa", priv, pkg.encrypted_aes_key, pkg.encrypted_message, associated_data=aad)
        else:
            recv_priv, recv_pub = generate_ecc_keypair()
            send_priv, send_pub = generate_ecc_keypair()
            sender_bytes = serialize_public_key(send_pub)
            aad = b"test-agent|ecc|" + sender_bytes
            pkg = encrypt_hybrid(b"policy-driven", method=method, public_key=recv_pub,
                                 sender_private_key=send_priv, associated_data=aad)
            result = decrypt_hybrid("ecc", recv_priv, pkg.encrypted_aes_key, pkg.encrypted_message,
                                    sender_public_key=send_pub, associated_data=aad)

        self.assertEqual(result, b"policy-driven")


if __name__ == "__main__":
    unittest.main(verbosity=2)
