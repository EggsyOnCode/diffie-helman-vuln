from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

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
# Simplified DH for demonstration (using small integers)
# In production, use cryptography.hazmat.primitives.asymmetric.dh
P = 23
G = 5

def generate_dh_pair():
    priv = 15  # Random integer in real life
    pub = pow(G, priv, P)
    return priv, pub

def compute_shared_secret(their_pub, my_priv):
    return pow(their_pub, my_priv, P)

# --- 3. The Protocol Execution ---

print("--- PHASE 1: PRE-EXISTING TRUST ---")
# Alice and Bob already have their long-term Identity Keys (RSA)
# In TLS, Alice checks Bob's Certificate to get bob_id_pub
alice_id_priv, alice_id_pub = generate_identity_keypair()
bob_id_priv, bob_id_pub = generate_identity_keypair()
print("[PKI] Identities established.")

print("\n--- PHASE 2: HANDSHAKE (Prevention of MITM) ---")

# Step A: Alice generates Ephemeral DH Key
alice_dh_priv, alice_dh_pub = generate_dh_pair()
# Alice sends Y_a to Bob (In TLS ClientHello)
print(f"[Alice] Sends ephemeral DH Public Key: {alice_dh_pub}")

# Step B: Bob generates Ephemeral DH Key
bob_dh_priv, bob_dh_pub = generate_dh_pair()

# --- THE SECURITY FIX ---
# Bob creates a signature over (Alice's Pub Key + Bob's Pub Key)
# This binds the current session to his Identity.
handshake_data = f"{alice_dh_pub}{bob_dh_pub}".encode()
bob_signature = sign_data(bob_id_priv, handshake_data)

print(f"[Bob] Sends ephemeral DH Public Key: {bob_dh_pub}")
print(f"[Bob] Sends RSA Signature of the handshake.")

# Step C: Eve attempts MITM (simulated)
# Eve can see the public keys, but she CANNOT generate a valid signature 
# for her fake key because she doesn't have bob_id_priv.

# Step D: Alice Verifies
received_dh_pub = bob_dh_pub # Assume no modification for success case
received_signature = bob_signature

# Alice reconstructs the data she expects to be signed
expected_data = f"{alice_dh_pub}{received_dh_pub}".encode()

if verify_signature(bob_id_pub, expected_data, received_signature):
    print("\n[Alice] Signature VERIFIED. The key definitely came from Bob.")
    secret = compute_shared_secret(received_dh_pub, alice_dh_priv)
    print(f"[Alice] Shared Secret Established: {secret}")
else:
    print("\n[Alice] SECURITY ALERT: Signature Failed! Possible MITM Attack.")