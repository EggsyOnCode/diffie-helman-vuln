"""
SECURE DIFFIE–HELLMAN (ECDHE) IMPLEMENTATION
------------------------------------------

This implementation uses Elliptic Curve Diffie–Hellman (ECDH) with
ephemeral keys and a Key Derivation Function (HKDF).

It is similar to what is used in TLS 1.3.
"""

# =============================
# CRYPTOGRAPHY LIBRARIES USED
# =============================

# ec  -> Elliptic Curve cryptography module
# Provides modern, secure Diffie–Hellman using elliptic curves
from cryptography.hazmat.primitives.asymmetric import ec

# hashes -> Cryptographic hash functions (SHA‑256 here)
# Used inside HKDF for key strengthening
from cryptography.hazmat.primitives import hashes

# HKDF -> HMAC‑based Key Derivation Function
# Used to convert raw shared secrets into strong symmetric keys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ==========================================================
# STEP 1: ALICE GENERATES AN EPHEMERAL ELLIPTIC CURVE KEY
# ==========================================================

# generate_private_key():
#   - Creates a cryptographically secure random private key
#   - Uses OS‑level secure randomness
#   - Ephemeral → used once, then discarded (Forward Secrecy)

# SECP256R1:
#   - NIST P‑256 curve
#   - Widely used and considered secure
#   - Provides ~128‑bit security

alice_private = ec.generate_private_key(ec.SECP256R1())

# public_key():
#   - Computes the public key from the private key
#   - Safe to share publicly
alice_public = alice_private.public_key()


# ==========================================================
# STEP 2: BOB GENERATES HIS EPHEMERAL ELLIPTIC CURVE KEY
# ==========================================================

bob_private = ec.generate_private_key(ec.SECP256R1())
bob_public = bob_private.public_key()


# ==========================================================
# STEP 3: ELLIPTIC CURVE DIFFIE–HELLMAN (ECDH)
# ==========================================================

# exchange():
#   - Performs the Diffie–Hellman key agreement
#   - Combines:
#       • Your private key
#       • Other party's public key
#   - Produces a SHARED SECRET

# ec.ECDH():
#   - Specifies the ECDH algorithm
#   - Prevents misuse with wrong algorithms

alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared   = bob_private.exchange(ec.ECDH(), alice_public)

# At this point:
#   alice_shared == bob_shared
# But this value is:
#   ❌ NOT directly suitable as an encryption key


# ==========================================================
# STEP 4: KEY DERIVATION FUNCTION (HKDF)
# ==========================================================

def derive_key(shared_secret):
    """
    HKDF (HMAC‑based Key Derivation Function)

    Why HKDF is necessary:
    ----------------------
    Raw Diffie–Hellman output:
    ❌ May have bias
    ❌ May not be uniform
    ❌ Should never be used directly as a key

    HKDF provides:
    ✔ Key strengthening
    ✔ Uniform randomness
    ✔ Domain separation
    """

    return HKDF(
        algorithm=hashes.SHA256(),
        # SHA‑256 provides cryptographic mixing

        length=32,
        # 32 bytes = 256‑bit symmetric key (AES‑256)

        salt=None,
        # Optional salt (TLS often uses transcript hash instead)

        info=b"secure-communication",
        # Context string:
        # Prevents key reuse across different purposes
        # Called "domain separation"

    ).derive(shared_secret)


# Derive final symmetric encryption keys
alice_key = derive_key(alice_shared)
bob_key   = derive_key(bob_shared)


# ==========================================================
# STEP 5: KEY CONFIRMATION
# ==========================================================

# Both parties verify they derived the same key
# This prevents silent MITM and protocol failures

print("Shared keys match:", alice_key == bob_key)
