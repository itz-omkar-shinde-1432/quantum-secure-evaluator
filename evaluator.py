import math

def estimate_password_strength(password):
    charset_size = 94
    length = len(password)

    classical_guesses = charset_size ** length
    quantum_guesses = math.isqrt(classical_guesses)

    print(f"Password: {password}")
    print(f"Length: {length}")
    print(f"Classical guesses: {classical_guesses:,}")
    print(f"Quantum guesses (Grover’s): {quantum_guesses:,}")

    if quantum_guesses < 1e6:
        rating = "🚫 Weak (Crackable in seconds)"
    elif quantum_guesses < 1e9:
        rating = "⚠️ Medium (Needs stronger password)"
    else:
        rating = "✅ Quantum-Safe"

    print(f"Rating: {rating}")
    return rating

# Try it
estimate_password_strength("Omkar@123")
