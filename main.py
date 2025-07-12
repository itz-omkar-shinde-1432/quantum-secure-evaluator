import math
import re
import random
import string
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit
from qiskit.visualization import plot_histogram
from qiskit_aer.primitives import Sampler

# ✅ Suggest strong password alternatives avoiding personal info

def suggest_improved_variants(password, count=5):
    substitutions = {
        'a': '@', 's': '$', 'i': '1', 'o': '0', 'e': '3', 'l': '1', 't': '7'
    }
    symbols = "!@#$%^&*()_-+=<>?/"

    variants = set()

    while len(variants) < count:
        pwd = ""
        for char in password:
            if char.lower() in substitutions and random.random() < 0.5:
                pwd += substitutions[char.lower()]
            else:
                pwd += char.upper() if random.random() < 0.3 else char

        # Add random symbol and number at random positions
        pwd = list(pwd)
        pwd.insert(random.randint(0, len(pwd)), random.choice(symbols))
        pwd.insert(random.randint(0, len(pwd)), str(random.randint(0, 9)))
        variants.add("".join(pwd))

    return list(variants)


# ✅ Detect charset size used in password
def detect_charset_size(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in "!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/" for c in password): size += 32
    return size

# 🔐 Calculate entropy
def password_entropy(password):
    charset = detect_charset_size(password)
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

# 📁 Check leaked password
def is_common_leaked_password(password):
    try:
        with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
            password = password.strip().lower()
            return any(password == line.strip().lower() for line in file)
    except FileNotFoundError:
        print("⚠️ rockyou.txt not found. Skipping leaked password check.")
    return False

# 📁 Check keyboard patterns from file
def is_keyboard_pattern(password):
    try:
        with open("keyboard_patterns.txt", "r", encoding="utf-8") as file:
            patterns = [line.strip().lower() for line in file if line.strip()]
            for pattern in patterns:
                if pattern in password.lower() or pattern[::-1] in password.lower():
                    return True
    except FileNotFoundError:
        print("⚠️ keyboard_patterns.txt not found. Skipping keyboard pattern check.")
    return False

# 📅 Detect date/year/mobile number patterns
def detect_personal_info_patterns(password):
    detections = []
    if re.search(r'(19[0-9]{2}|20[0-9]{2})', password):
        detections.append("⚠️ Contains a year (e.g., birth year)")
    if re.search(r'\b\d{8}\b', password):
        detections.append("⚠️ Contains a full date (DDMMYYYY or similar)")
    if re.search(r'\b\d{10}\b', password):
        detections.append("⚠️ Looks like a phone number")
    return detections

# 🧠 Pattern analysis
def analyze_patterns(password, personal_info_list=None):
    if personal_info_list is None:
        personal_info_list = []
    deductions = []

    if is_common_leaked_password(password):
        deductions.append("❌ This password is found in leaked data (rockyou.txt)")

    if is_keyboard_pattern(password):
        deductions.append("⚠️ Contains common keyboard pattern")

    common_words = ["password", "admin", "omkar", "qwerty", "123456", "iloveyou"]
    for word in common_words:
        if word.lower() in password.lower():
            deductions.append(f"⚠️ Contains common word or name: '{word}'")

    if re.search(r'(.)\1{2,}', password):
        deductions.append("⚠️ Contains repeated characters like 'aaa'")

    if re.match(r'^\d+$', password):
        deductions.append("⚠️ Only contains digits")

    if re.match(r'^[a-z]+$', password):
        deductions.append("⚠️ Only contains lowercase letters")

    if password and (password[0] in "!@#$%^&*" or password[-1] in "!@#$%^&*"):
        deductions.append("⚠️ Symbol only at start or end")

    for info in personal_info_list:
        if info and info.lower() in password.lower():
            deductions.append(f"⚠️ Contains personal info: '{info}'")

    return deductions

# 🔢 Estimate strength
def estimate_password_strength(password):
    charset_size = detect_charset_size(password) or 1
    length = len(password)
    classical_guesses = charset_size ** length
    quantum_guesses = math.isqrt(classical_guesses)

    print(f"\n🔐 Password: {password}")
    print(f"🔢 Length: {length}")
    print(f"🧮 Classical guesses: {classical_guesses:,}")
    print(f"⚛️ Quantum guesses (Grover’s): {quantum_guesses:,}")

    if is_common_leaked_password(password):
        rating = "🚫 Very Weak (Leaked Password)"
    elif quantum_guesses < 1e6:
        rating = "🚫 Weak (Crackable in seconds)"
    elif quantum_guesses < 1e9:
        rating = "⚠️ Medium (Breakable with effort)"
    else:
        rating = "✅ Quantum-Safe"

    print(f"💡 Rating: {rating}")
    return rating

# ⚛️ Quantum simulation
def simulate_quantum_search(bits=3):
    print("\n🧪 Simulating Quantum Superposition (Grover’s Style)...")
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

# 🚀 Main Execution
if __name__ == "__main__":
    print("🔒 Quantum Password Evaluator 🔒")
    print("💬 Would you like to enter some personal info to check if your password uses personal data?")
    print("    This helps us provide the best security analysis. (You can skip this.)")

    personal_info_list = []
    if input("🔸 Enter 'y' for yes or just press Enter to skip: ").strip().lower() == 'y':
        print("\n👉 Great! You can skip any of these questions by pressing Enter.\n")
        for label in ["name", "pet name", "birth year (e.g., 2005)", "birth date (DDMM)", "school or college name"]:
            data = input(f"🔸 Enter your {label}: ").strip()
            if data:
                personal_info_list.append(data.lower())
    else:
        print("🔐 Skipping personal info analysis.\n")

    user_password = input("Enter your password to check: ").strip()

    rating = estimate_password_strength(user_password)

    if "Weak" in rating:
        print("\n💡 Your password is weak. Consider using one of these secure variants:")
        suggestions = suggest_improved_variants(user_password)
        print("\n🔐 Suggested Passwords:")
        for s in suggestions:
            print("  -", s)

    print(f"🔐 Entropy: {password_entropy(user_password)} bits")

    pattern_warnings = analyze_patterns(user_password, personal_info_list)
    if pattern_warnings:
        print("\n🚨 Pattern Warnings:")
        for w in pattern_warnings:
            print("  -", w)

    personal_patterns = detect_personal_info_patterns(user_password)
    if personal_patterns:
        print("\n📅 Personal Info Warnings:")
        for p in personal_patterns:
            print("  -", p)

    simulate_quantum_search()
