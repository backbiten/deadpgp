import random
import string
import json
from core.audit import JSONLogger

class NonBinaryMimic:
    """
    Implements 'Non-Binary' encryption by transforming binary ciphertext 
    into innocuous natural language patterns or structured 'Dead' data.
    Goal: Evade persistence discovery by authorities and automated scanners.
    """
    def __init__(self):
        self.logger = JSONLogger()
        # Dictionary of 'Dead' fragments to build 'Living' messages
        self.corpus = [
            "The weather is fine today.",
            "Please remember to buy milk.",
            "I will be home by six.",
            "The document is attached for your review.",
            "Let's meet at the usual place.",
            "The system update is complete.",
            "Did you see the news about the merger?",
            "The cat is on the mat."
        ]

    def encode_to_natural_language(self, binary_data):
        """
        Transforms binary data into a sequence of corpus sentences.
        This is a 'Non-Binary' presence in persistence (email/logs).
        """
        # Simple mapping: each byte selects a sentence from the corpus
        encoded_message = []
        for byte in binary_data:
            index = byte % len(self.corpus)
            encoded_message.append(self.corpus[index])
        
        mimic_text = " ".join(encoded_message)
        self.logger.log_event("NON_BINARY_TRANSFORM", {"length": len(binary_data)})
        return mimic_text

    def create_dead_persistence_blob(self, metadata):
        """
        Creates a 'Persistence' blob that looks like a corrupted 32-bit log file.
        Hides the 'Living' intent inside 'Dead' system artifacts.
        """
        noise = "".join(random.choices(string.hexdigits, k=64))
        blob = {
            "sys_log_id": random.randint(1000, 9999),
            "status": "CRITICAL_FAILURE_32BIT_HYBRID",
            "payload_fragment": metadata,
            "checksum": noise
        }
        return json.dumps(blob)