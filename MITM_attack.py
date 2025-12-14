"""
 Man-in-the-Middle (MITM) demonstration
against an unauthenticated Diffie–Hellman implementation.

This code SIMULATES message interception and key substitution.
No real network attack is performed.
The user is unauthenticated, allowing Mallory to impersonate both parties.

"""

import random
from Diffie_helmen_implementation import is_primitive_root
from sympy import isprime

# -----------------------------
# Step 1: Global public values
# -----------------------------

def setup_global_parameters():
    q = 23   # small prime for demo
    a = 5    # primitive root of 23

    assert isprime(q), "q must be prime"
    assert is_primitive_root(a, q), "a must be a primitive root"

    print("[+] Global parameters agreed publicly")
    print(f"    q = {q}, alpha = {a}\n")
    return q, a


# -----------------------------
# Step 2: Alice and Bob setup
# -----------------------------

def generate_party_keys(name, q, a):
    private = random.randint(1, q - 1)
    public = pow(a, private, q)
    print(f"[+] {name} generates keys")
    print(f"    Private key: {private}")
    print(f"    Public key : {public}\n")
    return private, public


# -----------------------------
# Step 3: Mallory (MITM attacker)
# -----------------------------

def generate_mallory_keys(q, a):
    m1 = random.randint(1, q - 1)
    m2 = random.randint(1, q - 1)

    m1_pub = pow(a, m1, q)
    m2_pub = pow(a, m2, q)

    print("[!] Mallory (MITM) prepares fake public keys")
    print(f"    Fake public sent to Alice: {m1_pub}")
    print(f"    Fake public sent to Bob  : {m2_pub}\n")

    return (m1, m1_pub), (m2, m2_pub)


# -----------------------------
# Step 4: MITM key exchange
# -----------------------------

def mitm_exchange():
    q, a = setup_global_parameters()

    # Alice and Bob keys
    alice_priv, alice_pub = generate_party_keys("Alice", q, a)
    bob_priv, bob_pub = generate_party_keys("Bob", q, a)

    # Mallory keys
    (mA_priv, mA_pub), (mB_priv, mB_pub) = generate_mallory_keys(q, a)

    # Mallory intercepts and replaces public keys
    alice_received = mA_pub   # Alice thinks this is Bob's key
    bob_received = mB_pub     # Bob thinks this is Alice's key

    # Shared secrets
    alice_shared = pow(alice_received, alice_priv, q)
    bob_shared = pow(bob_received, bob_priv, q)

    mallory_alice_shared = pow(alice_pub, mA_priv, q)
    mallory_bob_shared = pow(bob_pub, mB_priv, q)

    print("=== Shared Secrets Computed ===")
    print(f"Alice computes:   {alice_shared}")
    print(f"Bob computes:     {bob_shared}")
    print(f"Mallory ↔ Alice:  {mallory_alice_shared}")
    print(f"Mallory ↔ Bob:    {mallory_bob_shared}\n")

    # Result analysis
    print("=== Attack Result ===")
    if alice_shared != bob_shared:
        print("[✔] Alice and Bob do NOT share the same secret")
        print("[✔] Mallory successfully established two secrets")
        print("[✔] Man-in-the-Middle attack SUCCESSFUL")
    else:
        print("[✘] MITM attack failed")


# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":
    print("\n===== MITM Attack Demonstration on Diffie–Hellman =====\n")
    mitm_exchange()
