# Diffie-Hellman Key Exchange Analysis & Improvement

This repository contains an analysis, implementation, and security enhancement of the **Diffie-Hellman Key Exchange Protocol**.

While the original Diffie-Hellman protocol revolutionized cryptography by allowing secure key exchange over public channels, it suffers from a critical lack of **authentication**. This project demonstrates that vulnerability via a Man-in-the-Middle (MITM) attack and proposes a concrete improvement using **Authenticated Diffie-Hellman (Station-to-Station protocol variant)** backed by RSA Digital Signatures.

## Project Overview

### 1\. Vulnerability Analysis

The standard Diffie-Hellman protocol is anonymous. Alice knows she is exchanging a key with *someone*, but she cannot verify that "someone" is Bob. This allows an attacker (Eve) to intercept public keys, replace them with her own, and establish separate encrypted connections with both Alice and Bob (MITM Attack).

### 2\. Proposed Improvement

We implemented **Authenticated Diffie-Hellman** by adding a Public Key Infrastructure (PKI) layer.

  * **Mechanism:** Both parties possess long-term RSA Identity Keys.
  * **Protocol Change:** Ephemeral Diffie-Hellman public keys are now digitally signed by the sender's RSA private key.
  * **Result:** Even if Eve intercepts the packet, she cannot tamper with the key because she cannot forge the digital signature.

-----

## Installation & Setup

This project uses **[uv](https://github.com/astral-sh/uv)** for fast Python dependency management.

1.  **Install uv** (if not installed):

    ```bash
    pip install uv
    ```

2.  **Sync Dependencies**:
    Navigate to the project folder and run:

    ```bash
    uv sync
    ```

    This will create the virtual environment and install the required libraries (including `sympy` for math and `cryptography` for the secure improvement).

-----

## Running the Demo

Follow these steps in order to walk through the analysis, attack, and defense.

### Step 1: Core Implementation

Run the standard Diffie-Hellman algorithm to see how it works under normal conditions.

```bash
uv run implementation.py
```

  * **What happens:** You will be prompted to enter a Prime ($q$) and a Primitive Root ($\alpha$).
  * **Output:** Alice and Bob successfully calculate the same Shared Secret ($K$).

### Step 2: The Attack (MITM)

Demonstrate the vulnerability by running a script where "Eve" sits in the middle of the network.

```bash
uv run attack_demo.py
```

  * **Scenario:** Eve intercepts Alice's public key, swaps it with her own, and forwards it to Bob (and vice-versa).
  * **Output:** You will see that Alice and Bob *think* they are secure, but Eve has successfully calculated the shared secret for both sides.
  * **Verdict:** Confidentiality is broken.

### Step 3: The Improvement (Authenticated DH)

Run the secure version of the protocol implementing Digital Signatures (RSA-PSS).

```bash
uv run authenticated_dh.py
```

  * **Scenario:** Alice and Bob now sign their ephemeral DH keys with their RSA Identity Keys before sending.
  * **Output:** The script demonstrates the verification process. You will see messages indicating `[Signature VERIFIED]`.
  * **Verdict:** A secure channel is established with Mutual Authentication.

### Step 4: Evaluation (Attack on Improvement)

Finally, we attempt to launch the exact same MITM attack on our improved protocol to prove it fails.

```bash
uv run attack_on_auth_dh.py
```

  * **Scenario:** Eve tries to swap the public keys again. However, she cannot forge the digital signature associated with the new key.
  * **Output:** Alice (or Bob) detects the mismatch between the key and the signature.
    ```text
    [Alice] SECURITY ALERT: Signature Verification Failed!
    [Alice] RESULT: Man-in-the-Middle Attack Detected and Blocked.
    ```
  * **Verdict:** The attack is successfully mitigated.

-----

## Technical Details

### Dependencies

  * **Python 3.10+**
  * **SymPy:** Used in the core implementation for primitive root validation.
  * **Cryptography:** Used in the improvement scripts for industry-standard RSA-PSS signing and SHA-256 hashing.

### File Structure

  * `implementation.py`: The baseline Diffie-Hellman (Textbook implementation).
  * `attack_demo.py`: Simulation of a MITM attack on the baseline.
  * `authenticated_dh.py`: The secure implementation using RSA Signatures.
  * `attack_on_auth_dh.py`: The evaluation script proving the security of the improvement.

## License

This project is open-source and free to use for educational purposes.