import random
from sympy import isprime


def is_primitive_root(a, q):
    """
    Check if 'a' is a primitive root modulo prime 'q'.
    """
    # List of exponents from 1 to q-1
    n = list(range(1, q))
    # Calculate a^n[i] mod q for each exponent i in the list
    computed = [pow(a, i, q) for i in n]

    # If a is a primitive root, computed values should be a permutation of [1, 2, ..., q-1]
    return sorted(computed) == n


def get_global_elements():
    while True:
        try:
            q = int(input("Enter a prime number q: "))
            if not isprime(q):
                print("Error: q must be a prime number. Try again.")
                continue
            while True:
                try:
                    a = int(input(f"Enter a base number alpha (must be a primitive root of {q} and less than {q}): "))
                    if a >= q:
                        print(f"Error: alpha must be less than {q}. Try again.")
                        continue
                    if not is_primitive_root(a, q):
                        print(f"Error: {a} is not a primitive root of {q}. Try again.")
                        continue
                    return q, a
                except ValueError:
                    print("Invalid input. Please enter a valid integer for alpha.")
        except ValueError:
            print("Invalid input. Please enter a valid prime number for q.")


print("Diffie-Hellman Key Exchange Algorithm")

q, a = get_global_elements()
print("Global elements")
print(f"Selected Prime (q): {q}, Primitive Root of q (alpha): {a}")

alice_private = random.randint(1, q-1)
alice_public = pow(a, alice_private, q)
print(f"Private Elements of Alice (Xa): {alice_private}, Public Element of Alice (Ya): {alice_public}")

bob_private = random.randint(1, q-1)
bob_public = pow(a, bob_private, q)
print(f"Private Elements of Bob (Xb): {bob_private}, Public Element of Bob (Yb): {bob_public}")

alice_shared = pow(bob_public, alice_private, q)
bob_shared = pow(alice_public, bob_private, q)

print(f"Alice's Shared Secret (Ka): {alice_shared}")
print(f"Bob's Shared Secret (Kb): {bob_shared}")

if alice_shared == bob_shared:
    print("Key exchange successful! The shared secret matches.")
else:
    print("Error: Shared secrets do not match!")
