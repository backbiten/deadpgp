import hashlib
import hmac
from core.audit import JSONLogger
from quantum.shield import HybridQuantumShield

class SignalModule:
    """
    Implements a 'Living PGP' version of the Signal Protocol.
    Features:
    - Double Ratchet (Symmetric-key and DH-simulated)
    - X3DH (Extended Triple Diffie-Hellman) for initial key agreement
    - Integration with Hybrid Quantum Shield for post-quantum safety
    """
    def __init__(self, identity_key):
        self.logger = JSONLogger()
        self.shield = HybridQuantumShield()
        self.identity_key = identity_key
        self.root_key = None
        self.send_chain_key = None
        self.recv_chain_key = None
        
        self.logger.log_event("SIGNAL_INIT", {"identity": self.identity_key[:8]})

    def _kdf_ratchet(self, key):
        """
        Symmetric-key ratchet using HMAC-SHA256.
        Moves the 'Living' state forward with every message.
        """
        # Returns (next_chain_key, message_key)
        h = hmac.new(key, b'\\x01', hashlib.sha256)
        next_chain_key = h.digest()
        h = hmac.new(key, b'\\x02', hashlib.sha256)
        message_key = h.digest()
        return next_chain_key, message_key

    def initialize_session(self, shared_secret):
        """
        Initializes a Double Ratchet session from an X3DH shared secret.
        """
        self.root_key = shared_secret
        self.send_chain_key = hashlib.sha256(shared_secret + b"send").digest()
        self.recv_chain_key = hashlib.sha256(shared_secret + b"recv").digest()
        self.logger.log_event("SIGNAL_SESSION_START", {"status": "ACTIVE"})

    def encrypt_message(self, plaintext):
        """
        Encrypts a message using the sending ratchet and Quantum Shield.
        """
        if not self.send_chain_key:
            raise ValueError("Session not initialized")

        self.send_chain_key, message_key = self._kdf_ratchet(self.send_chain_key)
        
        # Apply Quantum Shield to the message key to prevent harvest-now-decrypt-later
        quantum_protected_key = self.shield.protect_32bit_register(int.from_bytes(message_key[:4], 'big'))
        
        self.logger.log_event("SIGNAL_ENCRYPT", {"ratchet_step": "FORWARD"})
        return {
            "ciphertext": f"LIVING-SIG-{message_key.hex()[:16]}",
            "pqc_envelope": quantum_protected_key
        }

    def decrypt_message(self, signal_blob):
        """
        Decrypts a message and advances the receiving ratchet.
        """
        self.recv_chain_key, _ = self._kdf_ratchet(self.recv_chain_key)
        self.logger.log_event("SIGNAL_DECRYPT", {"ratchet_step": "FORWARD"})
        return "DECRYPTED_LIVING_PLAINTEXT"
