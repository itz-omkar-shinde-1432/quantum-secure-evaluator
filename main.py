"""
Quantum Password Evaluator

Author: Omkar Shinde
Date: July 2025

Description:
This tool analyzes passwords using classical security metrics like entropy,
pattern analysis, and known leaks (rockyou.txt), and incorporates quantum-inspired
methods, including a simulation of Grover's Algorithm to demonstrate how quantum
computing reduces brute-force attack complexity.

Features:
- Detects personal info, dates, and common patterns
- Estimates password entropy and strength
- Suggests stronger variants
- Simulates quantum superposition
- Implements Grover's Algorithm with Qiskit
- Demonstrates quantum cracking time vs password entropy
- Real Grover oracle for password index search (toy example)
"""

import math
import re
import random
import string
import matplotlib.pyplot as plt

from qiskit import QuantumCircuit, execute
from qiskit.visualization import plot_histogram
from qiskit_aer import Aer
from qiskit_aer.primitives import Sampler

# Suggest strong password variants
def suggest_improved_variants(password, count=5):
    substitutions = {'a': '@', 's': '$', 'i': '1', 'o': '0', 'e': '3', 'l': '1', 't': '7'}
    symbols = "!@#$%^&*()_-+=<>?/"
    variants = set()

    while len(variants) < count:
        pwd = ""
        for char in password:
            if char.lower() in substitutions and random.random() < 0.5:
                pwd += substitutions[char.lower()]
            else:
                pwd += char.upper() if random.random() < 0.3 else char

        pwd = list(pwd)
        pwd.insert(random.randint(0, len(pwd)), random.choice(symbols))
        pwd.insert(random.randint(0, len(pwd)), str(random.randint(0, 9)))
        variants.add("".join(pwd))

    return list(variants)

# Estimate character set size
def detect_charset_size(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in "!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/" for c in password): size += 32
    return size

# Shannon entropy calculation
def password_entropy(password):
    charset = detect_charset_size(password)
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

# Check for leaked passwords
def is_common_leaked_password(password):
    try:
        with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
            password = password.strip().lower()
            return any(password == line.strip().lower() for line in file)
    except FileNotFoundError:
        print("rockyou.txt not found. Skipping leaked password check.")
    return False

# Check common keyboard patterns
def is_keyboard_pattern(password):
    try:
        with open("keyboard_patterns.txt", "r", encoding="utf-8") as file:
            patterns = [line.strip().lower() for line in file if line.strip()]
            for pattern in patterns:
                if pattern in password.lower() or pattern[::-1] in password.lower():
                    return True
    except FileNotFoundError:
        print("keyboard_patterns.txt not found. Skipping keyboard pattern check.")
    return False

# Detect years, dates, mobile numbers
def detect_personal_info_patterns(password):
    detections = []
    if re.search(r'(19[0-9]{2}|20[0-9]{2})', password):
        detections.append("Contains a year (e.g., birth year)")
    if re.search(r'\b\d{8}\b', password):
        detections.append("Contains a full date (DDMMYYYY or similar)")
    if re.search(r'\b\d{10}\b', password):
        detections.append("Looks like a phone number")
    return detections

# Analyze patterns in the password
def analyze_patterns(password, personal_info_list=None):
    if personal_info_list is None:
        personal_info_list = []
    deductions = []

    if is_common_leaked_password(password):
        deductions.append("This password is found in leaked data (rockyou.txt)")
    if is_keyboard_pattern(password):
        deductions.append("Contains common keyboard pattern")

    common_words = ["password", "admin", "omkar", "qwerty", "123456", "iloveyou"]
    for word in common_words:
        if word.lower() in password.lower():
            deductions.append(f"Contains common word or name: '{word}'")

    if re.search(r'(.)\1{2,}', password):
        deductions.append("Contains repeated characters like 'aaa'")
    if re.match(r'^\d+$', password):
        deductions.append("Only contains digits")
    if re.match(r'^[a-z]+$', password):
        deductions.append("Only contains lowercase letters")
    if password and (password[0] in "!@#$%^&*" or password[-1] in "!@#$%^&*"):
        deductions.append("Symbol only at start or end")

    for info in personal_info_list:
        if info and info.lower() in password.lower():
            deductions.append(f"Contains personal info: '{info}'")

    return deductions

# Estimate classical vs quantum strength
def estimate_password_strength(password):
    charset_size = detect_charset_size(password) or 1
    length = len(password)
    classical_guesses = charset_size ** length
    quantum_guesses = math.isqrt(classical_guesses)

    print(f"Password: {password}")
    print(f"Length: {length}")
    print(f"Classical guesses: {classical_guesses:,}")
    print(f"Quantum guesses (Grover): {quantum_guesses:,}")

    if is_common_leaked_password(password):
        rating = "Very Weak (Leaked Password)"
    elif quantum_guesses < 1e6:
        rating = "Weak (Crackable in seconds)"
    elif quantum_guesses < 1e9:
        rating = "Medium (Breakable with effort)"
    else:
        rating = "Quantum-Safe"

    print(f"Rating: {rating}")
    return rating

# Quantum circuit to show superposition effect visually
def simulate_quantum_search(bits=3):
    print("Simulating quantum superposition (Grover style)...")
    qc = QuantumCircuit(bits)
    qc.h(range(bits))
    qc.measure_all()
    sampler = Sampler()
    result = sampler.run(qc).result()
    counts = result.quasi_dists[0]
    plot_histogram(counts)
    plt.title("Quantum Superposition Simulation")
    plt.savefig("quantum_histogram.png")
    plt.show()

# Grover's algorithm simulation with known index (toy cracking)
def run_grover_simulation(bits=3, target=3):
    print(f"Running Grover's Algorithm for target index: {format(target, f'0{bits}b')}")
    qc = QuantumCircuit(bits, bits)
    qc.h(range(bits))

    oracle = QuantumCircuit(bits)
    for idx, bit in enumerate(format(target, f"0{bits}b")):
        if bit == "0":
            oracle.x(idx)
    oracle.h(bits - 1)
    oracle.mct(list(range(bits - 1)), bits - 1)
    oracle.h(bits - 1)
    for idx, bit in enumerate(format(target, f"0{bits}b")):
        if bit == "0":
            oracle.x(idx)
    oracle.name = "Oracle"

    diffuser = QuantumCircuit(bits)
    diffuser.h(range(bits))
    diffuser.x(range(bits))
    diffuser.h(bits - 1)
    diffuser.mct(list(range(bits - 1)), bits - 1)
    diffuser.h(bits - 1)
    diffuser.x(range(bits))
    diffuser.h(range(bits))
    diffuser.name = "Diffuser"

    qc.append(oracle.to_gate(), range(bits))
    qc.append(diffuser.to_gate(), range(bits))
    qc.measure(range(bits), range(bits))

    backend = Aer.get_backend('qasm_simulator')
    result = execute(qc, backend, shots=1024).result()
    counts = result.get_counts()
    plot_histogram(counts)
    plt.title(f"Grover Search Output for Index {format(target, f'0{bits}b')}")
    plt.savefig("grover_output.png")
    plt.show()

# Main Execution
if __name__ == "__main__":
    print("Quantum Password Evaluator")
    print("You may optionally enter some personal information to detect weak usage.")

    personal_info_list = []
    if input("Enter 'y' to include personal info (optional): ").strip().lower() == 'y':
        print("Fill in any of the fields (press Enter to skip any):")
        for label in ["name", "pet name", "birth year (e.g., 2005)", "birth date (DDMM)", "school/college"]:
            data = input(f"{label}: ").strip()
            if data:
                personal_info_list.append(data.lower())

    password = input("Enter password to evaluate: ").strip()
    rating = estimate_password_strength(password)

    if "Weak" in rating:
        print("Suggested stronger variants:")
        for s in suggest_improved_variants(password):
            print(" -", s)

    print(f"Entropy: {password_entropy(password)} bits")

    for warning in analyze_patterns(password, personal_info_list):
        print("Warning:", warning)

    for warning in detect_personal_info_patterns(password):
        print("Warning:", warning)

    simulate_quantum_search()

    if input("Run Grover search simulation? (y/N): ").strip().lower() == 'y':
        try:
            bits = int(input("Enter number of qubits: "))
            target = int(input(f"Enter target value (0 to {2 ** bits - 1}): "))
            run_grover_simulation(bits, target)
        except:
            print("Invalid input. Skipping Grover simulation.")
