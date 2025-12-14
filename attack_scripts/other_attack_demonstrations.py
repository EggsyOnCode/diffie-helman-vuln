"""
ATTACK DEMONSTRATIONS ON BASIC DIFFIE–HELLMAN
=============================================

This file demonstrates three classic vulnerabilities that occur when
Diffie–Hellman is used WITHOUT authentication, freshness, or secure randomness.

ATTACKS SHOWN:
1. Replay Attack
2. Key-Confirmation Failure
3. Weak Randomness Attack

These attacks do NOT break cryptography.
They exploit protocol and implementation weaknesses.
"""

import random

# ======================================================
# COMMON DIFFIE–HELLMAN PARAMETERS (INSECURE DEMO VALUES)
# ======================================================

# q  -> public prime modulus
# a  -> generator (primitive root)
q = 23
a = 5


# ======================================================
# ATTACK 1: REPLAY ATTACK
# ======================================================

"""
DEFINITION:
-----------
A replay attack occurs when an attacker records a valid message
and replays it later, and the receiver accepts it as fresh.

ROOT CAUSE:
-----------
❌ No nonce
❌ No timestamp
❌ No session identifier
❌ No authentication

Diffie–Hellman alone does NOT provide freshness.
"""

print("\n====================")
print("1) REPLAY ATTACK")
print("====================")

# Alice generates a private key
alice_private = random.randint(1, q - 1)
alice_public = pow(a, alice_private, q)

print("Alice sends public key:", alice_public)

# Mallory records Alice's public key
recorded_alice_public = alice_public

# Later, Bob starts a new session
bob_private = random.randint(1, q - 1)

# Mallory replays Alice's OLD public key
bob_shared_replay = pow(recorded_alice_public, bob_private, q)

print("Bob accepts replayed key and derives:", bob_shared_replay)
print("Replay attack successful (no freshness check)")


# ======================================================
# ATTACK 2: KEY-CONFIRMATION FAILURE
# ======================================================

"""
DEFINITION:
-----------
Key confirmation ensures that BOTH parties have derived
the SAME shared secret.

ROOT CAUSE:
-----------
❌ No MAC
❌ No signature
❌ No confirmation message

Without key confirmation, a party may believe communication
is secure when it is not.
"""

print("\n==============================")
print("2) KEY CONFIRMATION FAILURE")
print("==============================")

# Alice generates DH values
alice_private = random.randint(1, q - 1)
alice_public = pow(a, alice_private, q)

# Mallory injects a fake public key to Bob
fake_alice_public = 8  # attacker-controlled value

bob_private = random.randint(1, q - 1)

# Bob derives a key using fake data
bob_shared = pow(fake_alice_public, bob_private, q)

print("Bob derived a key:", bob_shared)
print("Bob never verified Alice actually has this key")
print("Key confirmation failure allows silent attacks")


# ======================================================
# ATTACK 3: WEAK RANDOMNESS ATTACK
# ======================================================

"""
DEFINITION:
-----------
Weak randomness allows attackers to predict private keys.

ROOT CAUSE:
-----------
❌ random module is NOT cryptographically secure
❌ Predictable seed = predictable keys

This is NOT a mathematical weakness of Diffie–Hellman,
but an implementation flaw.
"""

print("\n=========================")
print("3) WEAK RANDOMNESS ATTACK")
print("=========================")

# Attacker guesses or forces PRNG seed
random.seed(42)

# Alice and Bob generate "random" private keys
alice_private = random.randint(1, q - 1)
bob_private = random.randint(1, q - 1)

alice_public = pow(a, alice_private, q)
bob_public = pow(a, bob_private, q)

shared_secret = pow(bob_public, alice_private, q)

print("Predicted Alice private key:", alice_private)
print("Predicted Bob private key:", bob_private)
print("Recovered shared secret:", shared_secret)

print("Weak randomness completely breaks Diffie–Hellman")


# ======================================================
# FINAL SUMMARY
# ======================================================

print("\n====================")
print("ATTACK SUMMARY")
print("====================")
print("Replay Attack            -> Lack of freshness")
print("Key Confirmation Failure -> No mutual verification")
print("Weak Randomness Attack   -> Predictable private keys")
