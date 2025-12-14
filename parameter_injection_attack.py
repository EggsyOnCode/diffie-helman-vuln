"""
Demonstration of Parameter Injection attack
against Diffie–Hellman using malicious generator.
"""

import random

# Public parameters (maliciously chosen)
q = 23
a = 1   # 🚨 malicious generator

print("[!] Malicious generator injected: a = 1")

# Alice
alice_private = random.randint(1, q - 1)
alice_public = pow(a, alice_private, q)

# Bob
bob_private = random.randint(1, q - 1)
bob_public = pow(a, bob_private, q)

# Shared secrets
alice_shared = pow(bob_public, alice_private, q)
bob_shared = pow(alice_public, bob_private, q)

print("\nAlice public key:", alice_public)
print("Bob public key:  ", bob_public)

print("\nAlice shared secret:", alice_shared)
print("Bob shared secret:  ", bob_shared)

if alice_shared == 1 and bob_shared == 1:
    print("\n[✔] Attack successful: shared secret is predictable (1)")
