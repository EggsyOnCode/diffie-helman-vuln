"""
Demonstration of lack of Forward Secrecy in Diffie–Hellman
"""

import random

# Public parameters
q = 23
a = 5

# Alice & Bob use STATIC private keys (bad practice)
alice_private = 6
bob_private = 15

alice_public = pow(a, alice_private, q)
bob_public = pow(a, bob_private, q)

print("[+] Public values exchanged")
print("Alice public:", alice_public)
print("Bob public:  ", bob_public)

# Shared secret (used to encrypt messages)
shared_secret = pow(bob_public, alice_private, q)

print("\n[+] Shared secret used for encryption:", shared_secret)

# -----------------------------
# Attacker records traffic
# -----------------------------

recorded_public_A = alice_public
recorded_public_B = bob_public

print("\n[!] Mallory records encrypted traffic...")

# -----------------------------
# Key compromise happens later
# -----------------------------

leaked_alice_private = alice_private  # leaked after the session

print("[!] Alice's private key leaked later:", leaked_alice_private)

# -----------------------------
# Retroactive decryption
# -----------------------------

recovered_secret = pow(recorded_public_B, leaked_alice_private, q)

print("\n[✔] Mallory recomputed shared secret:", recovered_secret)

if recovered_secret == shared_secret:
    print("[✔] Past communication fully compromised")
