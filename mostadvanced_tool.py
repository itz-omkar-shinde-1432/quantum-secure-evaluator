# Quantum Password Evaluator (Quantum+AI Pro Edition)

"""
Author: Omkar Shinde
Date: July 2025

Copyright (c) 2025 Omkar Shinde. All rights reserved.
Unauthorized copying of this file, via any medium is strictly prohibited.
Proprietary and confidential.

A powerful password security auditing tool combining Quantum Computing, Artificial Intelligence,
and Classical Heuristics. Built for educational, academic, and cybersecurity evaluation purposes.

Features:
- Entropy and brute-force effort estimation (Classical vs Quantum complexity)
- Real Grover’s Algorithm simulation using Qiskit
- IBMQ Cloud support (opt-in)
- Personal info leakage detection
- Pattern detection: keyboard sequences, common passwords, repeated characters, etc.
- Leaked password dictionary scan (rockyou.txt)
- Machine Learning-based scoring (custom logistic regression)
- Password strength suggestions
- Export to JSON + PDF
- Optional: Web API via FastAPI
- Optional: GUI via Streamlit
- CLI ready with argparse
- Logging & Modular structure for production
"""

import os
import re
import math
import json
import time
import random
import string
import logging
import argparse
import matplotlib.pyplot as plt
from typing import List
from fpdf import FPDF
from qiskit import QuantumCircuit, execute
from qiskit_aer import Aer
from qiskit.visualization import plot_histogram
from qiskit_ibm_provider import IBMProvider
from sklearn.linear_model import LogisticRegression
import joblib

# ======================== CONFIG & LOGGER ========================

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("QuantumPasswordEvaluator")

ROCKYOU_PATH = "rockyou.txt"
KEYBOARD_PATH = "keyboard_patterns.txt"
MODEL_PATH = "model.pkl"

# ======================== PASSWORD UTILITIES ========================

def detect_charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in string.punctuation for c in password): size += len(string.punctuation)
    return size or 1

def password_entropy(password: str) -> float:
    charset = detect_charset_size(password)
    return round(len(password) * math.log2(charset), 2)

def crack_time_estimate(guesses_per_second: float, total_guesses: int):
    seconds = total_guesses / guesses_per_second
    years = seconds / (60 * 60 * 24 * 365)
    months = years * 12
    return round(months, 2), round(years, 6)

# ======================== PATTERN DETECTION ========================

_leaked_passwords_cache = None
def is_common_leaked_password(password: str) -> bool:
    global _leaked_passwords_cache
    if _leaked_passwords_cache is None:
        try:
            with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
                _leaked_passwords_cache = set(line.strip().lower() for line in f)
        except FileNotFoundError:
            logger.warning("rockyou.txt not found")
            return False
    return password.strip().lower() in _leaked_passwords_cache

def is_keyboard_pattern(password: str) -> bool:
    try:
        with open(KEYBOARD_PATH, "r", encoding="utf-8") as f:
            patterns = [line.strip().lower() for line in f]
            return any(p in password.lower() or p[::-1] in password.lower() for p in patterns)
    except FileNotFoundError:
        logger.warning("keyboard_patterns.txt not found")
        return False

def detect_personal_info_patterns(password: str) -> List[str]:
    detections = []
    if re.search(r'(19[0-9]{2}|20[0-9]{2})', password):
        detections.append("Year detected")
    if re.search(r'\b\d{8}\b', password):
        detections.append("Full date format detected")
    if re.search(r'\b\d{10}\b', password):
        detections.append("Phone number pattern detected")
    return detections

def analyze_patterns(password: str, personal_info_list: List[str] = None) -> List[str]:
    deductions = []
    if is_common_leaked_password(password): deductions.append("Leaked password")
    if is_keyboard_pattern(password): deductions.append("Keyboard pattern detected")
    for word in ["password", "admin", "omkar", "qwerty", "123456"]:
        if word in password.lower():
            deductions.append(f"Common word: {word}")
    if re.search(r'(.)\1{2,}', password):
        deductions.append("Repeated characters")
    if re.match(r'^\d+$', password): deductions.append("Digits only")
    if re.match(r'^[a-z]+$', password): deductions.append("Lowercase only")
    if personal_info_list:
        for info in personal_info_list:
            if info.lower() in password.lower():
                deductions.append(f"Contains personal info: {info}")
    return deductions

# ======================== SUGGESTIONS ========================

def suggest_improved_variants(password: str, count=5) -> List[str]:
    substitutions = {'a': '@', 's': '$', 'i': '1', 'o': '0', 'e': '3', 'l': '1', 't': '7'}
    symbols = string.punctuation
    variants = set()
    while len(variants) < count:
        pwd = "".join(
            substitutions.get(c.lower(), c.upper() if random.random() < 0.3 else c) for c in password
        )
        pwd = list(pwd)
        pwd.insert(random.randint(0, len(pwd)), random.choice(symbols))
        pwd.insert(random.randint(0, len(pwd)), str(random.randint(0, 9)))
        variants.add("".join(pwd))
    return list(variants)

# ======================== STRENGTH ESTIMATION ========================

def estimate_password_strength(password: str):
    charset_size = detect_charset_size(password)
    length = len(password)
    classical_guesses = charset_size ** length
    quantum_guesses = math.isqrt(classical_guesses)
    classical_months, classical_years = crack_time_estimate(1e9, classical_guesses)
    quantum_months, quantum_years = crack_time_estimate(1e6, quantum_guesses)

    if is_common_leaked_password(password):
        strength = "Very Weak (Leaked)"
    elif quantum_guesses < 1e6:
        strength = "Weak"
    elif quantum_guesses < 1e9:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, classical_guesses, quantum_guesses, classical_months, classical_years, quantum_months, quantum_years

# ======================== QUANTUM SIMULATION ========================

def password_to_binary_index(password: str, password_list: List[str]) -> int:
    try:
        return password_list.index(password)
    except ValueError:
        return -1

def grover_search_simulation(password_list: List[str], target_password: str, backend_choice='local'):
    bits = math.ceil(math.log2(len(password_list)))
    index = password_to_binary_index(target_password, password_list)
    if index == -1:
        logger.warning("[!] Password not found in search space")
        return

    qc = QuantumCircuit(bits, bits)
    qc.h(range(bits))

    # Oracle
    oracle = QuantumCircuit(bits)
    binary = format(index, f'0{bits}b')
    for i, bit in enumerate(binary):
        if bit == '0': oracle.x(i)
    oracle.h(bits - 1)
    oracle.mcx(list(range(bits - 1)), bits - 1)
    oracle.h(bits - 1)
    for i, bit in enumerate(binary):
        if bit == '0': oracle.x(i)

    # Diffuser
    diffuser = QuantumCircuit(bits)
    diffuser.h(range(bits))
    diffuser.x(range(bits))
    diffuser.h(bits - 1)
    diffuser.mcx(list(range(bits - 1)), bits - 1)
    diffuser.h(bits - 1)
    diffuser.x(range(bits))
    diffuser.h(range(bits))

    iterations = int((math.pi / 4) * math.sqrt(2**bits))
    for _ in range(iterations):
        qc.append(oracle.to_gate(), range(bits))
        qc.append(diffuser.to_gate(), range(bits))

    qc.measure(range(bits), range(bits))
    backend = Aer.get_backend('qasm_simulator') if backend_choice == 'local' else IBMProvider().get_backend('ibmq_qasm_simulator')
    result = execute(qc, backend, shots=1024).result()
    counts = result.get_counts()
    plot_histogram(counts)
    plt.title("Grover's Algorithm Output")
    plt.show()

# ======================== MACHINE LEARNING ========================

def ml_password_score(password: str) -> float:
    try:
        model = joblib.load(MODEL_PATH)
        features = [len(password), detect_charset_size(password), password_entropy(password)]
        return model.predict_proba([features])[0][1]
    except Exception as e:
        logger.error("[ML] Model error: %s", e)
        return 0.0

# ======================== EXPORT REPORT ========================

def export_report_json(data, filename="report.json"):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def export_report_pdf(data, filename="report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for key, value in data.items():
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        pdf.multi_cell(0, 10, txt=f"{key}: {value}")
    pdf.output(filename)

# ======================== MAIN CLI ========================

def main():
    parser = argparse.ArgumentParser(description="Quantum+AI Password Security Evaluator")
    parser.add_argument("password", help="Password to evaluate")
    parser.add_argument("--personal", nargs='*', help="Personal info for detection", default=[])
    parser.add_argument("--simulate", action='store_true', help="Run Grover simulation")
    parser.add_argument("--export", action='store_true', help="Export JSON and PDF report")
    args = parser.parse_args()

    pwd = args.password
    personal_info = args.personal

    logger.info("Evaluating password: %s", pwd)

    strength, classical_guesses, quantum_guesses, classical_months, classical_years, quantum_months, quantum_years = estimate_password_strength(pwd)
    entropy = password_entropy(pwd)
    issues = analyze_patterns(pwd, personal_info)
    info_hits = detect_personal_info_patterns(pwd)
    suggestions = suggest_improved_variants(pwd)
    score = ml_password_score(pwd)

    print("\n--- Password Analysis Report ---")
    print("Entropy:", entropy, "bits")
    print("ML Score:", round(score, 3))
    print("Strength:", strength)
    print("Classical Crack Time:", classical_years, "years")
    print("Quantum Crack Time:", quantum_years, "years")
    if issues:
        print("Issues:", ", ".join(issues))
    if suggestions:
        print("Suggestions:", ", ".join(suggestions))

    report = {
        "Password": pwd,
        "Entropy": entropy,
        "Strength": strength,
        "ML_Score": score,
        "Classical_Guesses": classical_guesses,
        "Quantum_Guesses": quantum_guesses,
        "Classical_Crack_Years": classical_years,
        "Quantum_Crack_Years": quantum_years,
        "Issues": issues,
        "Personal_Hits": info_hits,
        "Suggestions": suggestions
    }

    if args.export:
        export_report_json(report)
        export_report_pdf(report)
        print("[+] Report exported to JSON and PDF.")

    if args.simulate:
        sample_dataset = ["admin", "123456", "omkar@2001", pwd]
        grover_search_simulation(sample_dataset, pwd, backend_choice='local')

if __name__ == "__main__":
    main()
