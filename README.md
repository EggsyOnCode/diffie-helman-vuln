# Diffie-Hellman Key Exchange  

This repository contains an implementation of the **Diffie-Hellman Key Exchange Protocol** in Python. The Diffie-Hellman algorithm allows two parties to securely establish a shared secret over an insecure channel without directly transmitting the secret itself.  

## Features  
- Allows users to input a prime number (**q**) and a primitive root (**α**) of that prime.  
- Validates whether the chosen **α** is a primitive root of **q**.  
- Generates private keys for Alice and Bob.  
- Computes public keys based on the private keys.  
- Derives a shared secret using modular exponentiation.  
- Ensures both parties compute the same shared secret.  

## How It Works  
1. The user inputs a prime number (**q**) and a primitive root (**α**) of **q**.  
2. Alice and Bob each generate a private key (**Xa**, **Xb**) randomly.  
3. Their public keys (**Ya**, **Yb**) are computed using modular exponentiation.  
4. Each party derives the shared secret by raising the received public key to their private key modulo **q**.  
5. If the computed shared secrets match, the key exchange is successful.  

## Usage  
Run the script in Python and follow the prompts to enter a prime number and a primitive root. The program will generate keys and establish a shared secret securely.  

## Example Output  
```
Diffie-Hellman Key Exchange Protocol  

Enter a prime number q: 23  
Enter a base number alpha (must be a primitive root of 23 and less than 23): 5  

Global elements  
Selected Prime: 23, Primitive Root of q (alpha): 5  

Private Elements of Alice (Xa): 6, Public Element of Alice (Ya): 8  
Private Elements of Bob (Xb): 15, Public Element of Bob (Yb): 19  

Alice's Shared Secret (Ka): 2  
Bob's Shared Secret (Kb): 2  

Key exchange successful! The shared secret matches.
```

## Dependencies  
- Python 3  
- `sympy` (for prime checking and modular inverse calculations)  

## License  
This project is open-source and free to use.
