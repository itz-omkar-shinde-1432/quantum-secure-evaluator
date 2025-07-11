'''
Quantum Password Evaluator (Advanced Edition)

Author: Omkar Shinde
Date: July 2025

Description:
An advanced quantum-aware password analysis tool combining classical password analysis techniques
with an actual working simulation of Grover's Algorithm. This application aims to demonstrate the quantum
speedup in brute-force attacks by simulating the retrieval of a password from a known list.

Key Features:
- Evaluates password entropy and character set strength
- Detects leaked passwords, personal info, common patterns, and keyboard sequences
- Estimates brute-force effort: classical vs quantum (Grover-based)
- Suggests improved password variants
- Performs Grover's quantum search simulation to find a target password
- Visualization of histogram result for Grover's outcome
- Ready for academic or research extension (modular, clear design)
'''

import math
import re
import random
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit, execute
from qiskit_aer import Aer
from qiskit.visualization import plot_histogram
from qiskit_aer.primitives import Sampler

# ========== PASSWORD UTILITIES ==========

def detect_charset_size(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in "!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/" for c in password): size += 32
    return size

def password_entropy(password):
    charset = detect_charset_size(password)
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def is_common_leaked_password(password):
    try:
        with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
            return any(password.strip().lower() == line.strip().lower() for line in file)
    except FileNotFoundError:
        return False

def is_keyboard_pattern(password):
    try:
        with open("keyboard_patterns.txt", "r", encoding="utf-8") as file:
            patterns = [line.strip().lower() for line in file]
            for pattern in patterns:
                if pattern in password.lower() or pattern[::-1] in password.lower():
                    return True
    except FileNotFoundError:
        return False
    return False

def detect_personal_info_patterns(password):
    detections = []
    if re.search(r'(19[0-9]{2}|20[0-9]{2})', password):
        detections.append("Year detected")
    if re.search(r'\b\d{8}\b', password):
        detections.append("Full date format detected")
    if re.search(r'\b\d{10}\b', password):
        detections.append("Phone number pattern detected")
    return detections

def analyze_patterns(password, personal_info_list=None):
    deductions = []
    if is_common_leaked_password(password):
        deductions.append("Leaked password")
    if is_keyboard_pattern(password):
        deductions.append("Keyboard pattern detected")

    common_words = ["password", "admin", "omkar", "qwerty", "123456"]
    for word in common_words:
        if word.lower() in password.lower():
            deductions.append(f"Common word detected: {word}")

    if re.search(r'(.)\1{2,}', password):
        deductions.append("Repeated characters")
    if re.match(r'^\d+$', password):
        deductions.append("Digits only")
    if re.match(r'^[a-z]+$', password):
        deductions.append("Lowercase only")
    for info in personal_info_list or []:
        if info.lower() in password.lower():
            deductions.append(f"Contains personal info: {info}")
    return deductions

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

# ========== STRENGTH EVALUATION ==========

def estimate_password_strength(password):
    charset_size = detect_charset_size(password) or 1
    length = len(password)
    classical_guesses = charset_size ** length
    quantum_guesses = math.isqrt(classical_guesses)

    print("\n[+] Classical guess space:", f"{classical_guesses:,}")
    print("[+] Quantum Grover guesses:", f"{quantum_guesses:,}")

    if is_common_leaked_password(password):
        return "Very Weak (Leaked)"
    elif quantum_guesses < 1e6:
        return "Weak"
    elif quantum_guesses < 1e9:
        return "Moderate"
    else:
        return "Strong"

# ========== QUANTUM SIMULATION (ACTUAL SEARCH) ==========

def password_to_binary_index(password, password_list):
    try:
        return password_list.index(password)
    except ValueError:
        return -1

def grover_search_simulation(password_list, target_password):
    bits = math.ceil(math.log2(len(password_list)))
    index = password_to_binary_index(target_password, password_list)
    if index == -1:
        print("[!] Target password not found in dataset.")
        return

    print(f"[Quantum] Searching for password at index {index} (binary {format(index, f'0{bits}b')})")
    qc = QuantumCircuit(bits, bits)
    qc.h(range(bits))

    # Grover's Oracle
    oracle = QuantumCircuit(bits)
    binary = format(index, f'0{bits}b')
    for i, bit in enumerate(binary):
        if bit == '0':
            oracle.x(i)
    oracle.h(bits - 1)
    oracle.mcx(list(range(bits - 1)), bits - 1)  # updated to mcx()
    oracle.h(bits - 1)
    for i, bit in enumerate(binary):
        if bit == '0':
            oracle.x(i)

    # Diffuser (Grover's amplifier)
    diffuser = QuantumCircuit(bits)
    diffuser.h(range(bits))
    diffuser.x(range(bits))
    diffuser.h(bits - 1)
    diffuser.mcx(list(range(bits - 1)), bits - 1)  # updated to mcx()
    diffuser.h(bits - 1)
    diffuser.x(range(bits))
    diffuser.h(range(bits))

    iterations = int((math.pi / 4) * math.sqrt(2**bits))
    for _ in range(iterations):
        qc.append(oracle.to_gate(), range(bits))
        qc.append(diffuser.to_gate(), range(bits))

    qc.measure(range(bits), range(bits))

    backend = Aer.get_backend('qasm_simulator')
    result = execute(qc, backend, shots=1024).result()
    counts = result.get_counts()
    plot_histogram(counts)
    plt.title("Grover Search Result")
    plt.show()

# ========== MAIN ==========

if __name__ == "__main__":
    print("[Quantum Password Evaluator] Advanced Edition\n")

    personal_info = []
    if input("Include personal info for analysis? (y/n): ").lower() == 'y':
        for label in ["name", "birth year", "college"]:
            value = input(f"Enter {label} (or press Enter to skip): ").strip()
            if value:
                personal_info.append(value)

    user_pwd = input("Enter password to evaluate: ").strip()
    rating = estimate_password_strength(user_pwd)
    print(f"\n[+] Strength Rating: {rating}")

    entropy = password_entropy(user_pwd)
    print(f"[+] Entropy: {entropy} bits")

    deductions = analyze_patterns(user_pwd, personal_info)
    if deductions:
        print("[!] Issues found:")
        for d in deductions:
            print(" -", d)

    personal_hits = detect_personal_info_patterns(user_pwd)
    for p in personal_hits:
        print(" -", p)

    if "Weak" in rating:
        print("\n[!] Suggested stronger variants:")
        for variant in suggest_improved_variants(user_pwd):
            print(" -", variant)

    small_set = ["apple123", "omkar@2001", "helloWorld", "admin", "iloveyou", user_pwd]
    grover_search_simulation(small_set, user_pwd)