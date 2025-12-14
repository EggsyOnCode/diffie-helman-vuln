import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# --- 1. PKI Setup (The "Trusted" Layer) ---
def generate_identity_keypair():
    """Generates a long-term RSA keypair for signing (Identity)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(identity_private_key, data):
    """Signs data (bytes) using the Identity Private Key."""
    signature = identity_private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(identity_public_key, data, signature):
    """Verifies that 'data' was signed by the owner of 'identity_public_key'."""
    try:
        identity_public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# --- 2. Diffie-Hellman Setup (The "Session" Layer) ---
P = 23
G = 5

def generate_dh_pair(priv_input=None):
    # If no private key provided, pick a random one
    if priv_input is None:
        priv = random.randint(1, P-1)
    else:
        priv = priv_input
    pub = pow(G, priv, P)
    return priv, pub

def compute_shared_secret(their_pub, my_priv):
    return pow(their_pub, my_priv, P)

# --- 3. The Protocol Execution (Simulating the Attack) ---

print("--- PHASE 1: PRE-EXISTING TRUST ---")
alice_id_priv, alice_id_pub = generate_identity_keypair()
bob_id_priv, bob_id_pub = generate_identity_keypair()
print("[PKI] Identities established.")

print("\n--- PHASE 2: HANDSHAKE BEGINS ---")

# 1. Alice generates her ephemeral key
alice_dh_priv, alice_dh_pub = generate_dh_pair()
print(f"[Alice] Sends ephemeral DH Public Key: {alice_dh_pub}")

# 2. Bob generates his ephemeral key
bob_dh_priv, bob_dh_pub = generate_dh_pair()
print(f"[Bob] Generates ephemeral DH Public Key: {bob_dh_pub}")

# 3. Bob signs the handshake (Alice's Key + Bob's Key)
#    This proves "I, Bob, received Alice's key {alice_dh_pub} and I am sending {bob_dh_pub}"
handshake_data_original = f"{alice_dh_pub}{bob_dh_pub}".encode()
bob_signature = sign_data(bob_id_priv, handshake_data_original)
print(f"[Bob] Signs the data: '{alice_dh_pub}{bob_dh_pub}'")
print(f"[Bob] Sends Packet: [Key: {bob_dh_pub} | Sig: <bytes>]")

print("\n--- PHASE 3: THE ATTACK (MITM) ---")

# 4. Eve Intercepts Bob's Packet
print("[!] EVE INTERCEPTS THE PACKET FROM BOB!")

# Eve generates her own malicious key
eve_dh_priv, eve_dh_pub = generate_dh_pair() 
# Ensure Eve's key is actually different for the demo
while eve_dh_pub == bob_dh_pub:
    eve_dh_priv, eve_dh_pub = generate_dh_pair()

print(f"[Eve] Throws away Bob's key ({bob_dh_pub}) and injects her own ({eve_dh_pub})")
print(f"[Eve] Forwards Bob's original signature (she cannot forge a new one).")

# The "Packet" Alice receives
received_dh_pub = eve_dh_pub      # MODIFIED BY EVE
received_signature = bob_signature # ORIGINAL FROM BOB

print("\n--- PHASE 4: ALICE VERIFIES ---")

# 5. Alice attempts to verify
# Alice believes she is talking to Bob.
# She expects the signature to cover: (What She Sent) + (What She Received)
data_alice_expects = f"{alice_dh_pub}{received_dh_pub}".encode()

print(f"[Alice] Verifying signature against data: '{alice_dh_pub}{received_dh_pub}'")

is_valid = verify_signature(bob_id_pub, data_alice_expects, received_signature)

if is_valid:
    # This should NOT happen in this attack scenario
    print("\n[Alice] Signature VERIFIED. (This means the attack failed or crypto is broken)")
    secret = compute_shared_secret(received_dh_pub, alice_dh_priv)
else:
    # This MUST happen for the demo to be successful
    print("\n[Alice] SECURITY ALERT: Signature Verification Failed!")
    print("[Alice] Analysis: The key I received was NOT the one Bob signed.")
    print("[Alice] RESULT: Man-in-the-Middle Attack Detected and Blocked.")