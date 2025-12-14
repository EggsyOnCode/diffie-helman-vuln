"""
Attempted MITM attack against authenticated Diffie–Hellman.
This demonstrates FAILURE due to signature verification.
"""

import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# -----------------------------
# Helper functions
# -----------------------------

def generate_rsa_keys():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return priv, priv.public_key()


def sign(priv, msg: bytes):
    return priv.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(pub, sig, msg: bytes):
    pub.verify(
        sig,
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# -----------------------------
# Setup
# -----------------------------

q = 23
a = 5

# Alice DH + signature keys
alice_priv = random.randint(1, q - 1)
alice_pub = pow(a, alice_priv, q)
alice_sig_priv, alice_sig_pub = generate_rsa_keys()

# Bob signature keys
bob_sig_priv, bob_sig_pub = generate_rsa_keys()

# Alice signs her DH public key
alice_msg = str(alice_pub).encode()
alice_signature = sign(alice_sig_priv, alice_msg)

print("[+] Alice sends signed DH public key")

# -----------------------------
# Mallory modifies key
# -----------------------------

mallory_fake_pub = 1  # malicious replacement
tampered_msg = str(mallory_fake_pub).encode()

print("[!] Mallory replaces Alice's DH public key")

# -----------------------------
# Bob verifies (attack fails here)
# -----------------------------

try:
    verify(alice_sig_pub, alice_signature, tampered_msg)
    print("[✘] MITM succeeded (this should never happen)")
except InvalidSignature:
    print("[✔] MITM attack detected!")
    print("[✔] Signature verification failed")
