"""
Quantum Password Evaluator API (Quantum+AI Pro Edition)

Author: Omkar Shinde
Date: July 2025

This FastAPI service exposes the password evaluation logic through a simple REST API.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import math

from mostadvanced import (
    password_entropy,
    estimate_password_strength,
    analyze_patterns,
    detect_personal_info_patterns,
    suggest_improved_variants,
    ml_password_score
)

app = FastAPI(
    title="Quantum Password Evaluator API",
    description="API for evaluating password strength using entropy, ML, quantum simulation, and classical analysis.",
    version="0.1.2"
)

# Request model
class PasswordInput(BaseModel):
    password: str
    personal_info: List[str] = []

# Response model
class EvaluationResult(BaseModel):
    password: str
    score: float
    entropy: float
    strength: str
    classical_guesses: int
    quantum_guesses: int
    crack_time_classical_years: float
    crack_time_quantum_years: float
    issues: List[str]
    personal_hits: List[str]
    suggestions: List[str]

# API Endpoint
@app.post("/evaluate", response_model=EvaluationResult)
def evaluate(input_data: PasswordInput):
    """
    Evaluate a password based on classical, AI, and quantum-inspired metrics.
    """
    password = input_data.password
    personal_info = input_data.personal_info

    # Core evaluation logic
    entropy = password_entropy(password)
    strength, classical_guesses, quantum_guesses, c_months, c_years, q_months, q_years = estimate_password_strength(password)
    issues = analyze_patterns(password, personal_info)
    personal_hits = detect_personal_info_patterns(password)
    score = ml_password_score(password)
    suggestions = suggest_improved_variants(password) if strength != "Strong" else []

    return EvaluationResult(
        password=password,
        score=round(score, 3),
        entropy=entropy,
        strength=strength,
        classical_guesses=classical_guesses,
        quantum_guesses=quantum_guesses,
        crack_time_classical_years=round(c_years, 2),
        crack_time_quantum_years=round(q_years, 2),
        issues=issues,
        personal_hits=personal_hits,
        suggestions=suggestions
    )
