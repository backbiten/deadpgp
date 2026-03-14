import unittest
import hashlib
import os
from core.aes512 import AES512Standard
from core.rsa4096 import RSA4096Standard
from quantum.shield import HybridQuantumShield

class TestLivingPGPStrength(unittest.TestCase):
    def setUp(self):
        self.aes_engine = AES512Standard()
        self.rsa_engine = RSA4096Standard()
        self.shield = HybridQuantumShield()

    def test_aes_512_entropy_and_state(self):
        entropy = os.urandom(64)
        key_512 = self.aes_engine.derive_512_key(entropy)
        self.assertEqual(len(key_512), 64)
        
        entropy_prime = bytearray(entropy)
        entropy_prime[0] ^= 0x01
        key_prime = self.aes_engine.derive_512_key(bytes(entropy_prime))
        self.assertNotEqual(key_512, key_prime)

    def test_rsa_4096_quorum_and_wrap(self):
        session_key = os.urandom(64)
        dummy_pub_key = b"RSA-4096-PUBLIC-KEY-DATA"
        result = self.rsa_engine.wrap_session_key(session_key, dummy_pub_key)
        self.assertIn('envelope', result)
        self.assertEqual(result['envelope']['algorithm'], 'RSA-4096')

        legacy_metadata = {'bits': 2048, 'id': 'legacy_user'}
        is_valid = self.rsa_engine.validate_key_strength(legacy_metadata)
        self.assertFalse(is_valid)

    def test_hybrid_quantum_shield_integrity(self):
        status = self.shield.flag_illegal_operation('MD5')
        self.assertEqual(status['status'], 'VETO_REQUIRED')
        
        reg_32 = 0xDEADBEEF
        envelope = self.shield.protect_32bit_register(reg_32)
        self.assertTrue(envelope.startswith('PQC-SIG-'))

if __name__ == '__main__':
    unittest.main()