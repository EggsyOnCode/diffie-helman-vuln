import random

# Man In The Middle Attack Demo

def get_public_key(g, private_key, p):
    return pow(g, private_key, p)

def get_shared_secret(public_key_sender, private_key_receiver, p):
    return pow(public_key_sender, private_key_receiver, p)

# --- Simulation Parameters ---
# Hardcoding these for the demo
p = 23   # A small prime for demonstration
g = 5    # A primitive root for 23

print(f"--- NETWORK SETUP ---\nPrime (p): {p}, Generator (g): {g}\n")

# --- 1. Alice Generates Keys ---
alice_priv = random.randint(1, p-1)
alice_pub = get_public_key(g, alice_priv, p)
print(f"[Alice] Generated Public Key: {alice_pub}")

# --- ATTACK: Eve Intercepts Alice's Message ---
print("\n[!] ATTACK: Eve intercepts Alice's packet...")
eve_priv = random.randint(1, p-1)
eve_pub = get_public_key(g, eve_priv, p)
print(f"[Eve] Generated Fake Public Key: {eve_pub}")
print(f"[Eve] Sends {eve_pub} to Bob (pretending to be Alice).")

# --- 2. Bob Receives Eve's Key (thinking it's Alice) ---
bob_received_pub = eve_pub  # Bob gets Eve's key, not Alice's
bob_priv = random.randint(1, p-1)
bob_pub = get_public_key(g, bob_priv, p)
bob_shared_secret = get_shared_secret(bob_received_pub, bob_priv, p)
print(f"\n[Bob] Generated Public Key: {bob_pub}")
print(f"[Bob] Calculated Shared Secret: {bob_shared_secret}")

# --- ATTACK: Eve Intercepts Bob's Message ---
print("\n[!] ATTACK: Eve intercepts Bob's packet...")
print(f"[Eve] Intercepts Bob's Key ({bob_pub}).")
print(f"[Eve] Sends {eve_pub} to Alice (pretending to be Bob).")

# --- 3. Alice Receives Eve's Key (thinking it's Bob) ---
alice_received_pub = eve_pub
alice_shared_secret = get_shared_secret(alice_received_pub, alice_priv, p)
print(f"\n[Alice] Calculated Shared Secret: {alice_shared_secret}")

# --- 4. Eve Decrypts Everything ---
# Eve calculates the secret she shares with Alice
eve_secret_alice = get_shared_secret(alice_pub, eve_priv, p)
# Eve calculates the secret she shares with Bob
eve_secret_bob = get_shared_secret(bob_pub, eve_priv, p)

print(f"\n--- ATTACK RESULTS ---")
print(f"Alice's Secret: {alice_shared_secret}")
print(f"Eve's Secret (w/ Alice): {eve_secret_alice} <--- MATCH!")
print(f"Bob's Secret:   {bob_shared_secret}")
print(f"Eve's Secret (w/ Bob):   {eve_secret_bob}   <--- MATCH!")

if alice_shared_secret == eve_secret_alice and bob_shared_secret == eve_secret_bob:
    print("\n[SUCCESS] Man-in-the-Middle successful! Eve can decrypt messages from both sides.")