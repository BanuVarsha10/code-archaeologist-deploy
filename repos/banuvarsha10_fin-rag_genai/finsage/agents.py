"""
agents.py — Final Fixed Version (stable + controlled reasoning + strong advice)
"""

from groq import Groq
from rag import search


# ── Agent 1: Profile ──────────────────────────────────────
def profile_agent(income, expenses, age, goal, emi=0):
    savings = income - expenses - emi
    savings_rate = round((savings / income) * 100, 1) if income > 0 else 0

    profile = {
        "income": income,
        "expenses": expenses,
        "emi": emi,
        "age": age,
        "goal": goal,
        "monthly_savings": savings,
        "savings_rate_pct": savings_rate,
        "overspending": savings < 0
    }

    return profile


# ── Agent 2: Risk ─────────────────────────────────────────
def risk_agent(profile):
    income = profile["income"]
    expenses = profile["expenses"]
    emi = profile["emi"]
    savings = profile["monthly_savings"]
    age = profile["age"]

    # Adaptive budgeting
    needs = expenses + emi
    remaining = income - needs

    if remaining <= 0:
        wants = 0
        savings_alloc = 0
        plan_type = "Survival Mode"
    else:
        savings_alloc = round(0.5 * remaining)
        wants = remaining - savings_alloc
        plan_type = "Adaptive Budget"

    savings_rate = savings / income if income > 0 else 0
    expense_ratio = needs / income if income > 0 else 1

    # Expense label
    if expense_ratio < 0.3:
        expense_label = "low"
    elif expense_ratio < 0.5:
        expense_label = "moderate"
    else:
        expense_label = "high"

    # Age score
    if age < 25:
        age_score = 0.9
    elif age < 40:
        age_score = 0.7
    elif age < 60:
        age_score = 0.5
    else:
        age_score = 0.3

    # Stability score
    if savings_rate > 0.5:
        stability_score = 0.9
    elif savings_rate > 0.3:
        stability_score = 0.7
    elif savings_rate > 0.1:
        stability_score = 0.5
    else:
        stability_score = 0.2

    # Expense burden score
    if expense_ratio < 0.3:
        burden_score = 0.9
    elif expense_ratio < 0.5:
        burden_score = 0.7
    else:
        burden_score = 0.4

    # Final risk score
    risk_score = round(
        0.4 * age_score +
        0.3 * stability_score +
        0.3 * burden_score,
        2
    )

    if risk_score > 0.7:
        risk_level = "High Risk Tolerance"
    elif risk_score > 0.5:
        risk_level = "Moderate"
    else:
        risk_level = "Conservative"

    return {
        **profile,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "needs": needs,
        "wants": wants,
        "recommended_savings": savings_alloc,
        "expense_ratio": round(expense_ratio, 2),
        "expense_label": expense_label,
        "plan_type": plan_type
    }


# ── Agent 3: Retrieval (IMPROVED) ─────────────────────────
def retrieval_agent(profile, index, texts, sources, model, k=5):
    query = f"{profile['goal']} investment strategy age {profile['age']} risk {profile['risk_level']} mutual funds bonds asset allocation retirement planning"
    chunks = search(query, index, texts, sources, model, k=k)
    return {**profile, "retrieved_chunks": chunks}


# ── Agent 4: Reasoning (FINAL FIXED) ──────────────────────
def reasoning_agent(profile, groq_client):
    p = profile

    context = "\n".join([
        f"[{c['source']}]: {c['text'][:200]}"
        for c in p["retrieved_chunks"]
    ])

    prompt = f"""
You are an Explainable Financial AI.

CRITICAL RULES:
- Use ONLY the given data
- Do NOT assume or change values
- Use exact age: {p['age']}
- Do NOT use vague words like "significant" or "substantial"
- Always relate expenses to income

USER DATA:
Income: ₹{p['income']}
Expenses: ₹{p['expenses']}
EMI: ₹{p['emi']}
Savings: ₹{p['monthly_savings']} ({p['savings_rate_pct']}%)
Age: {p['age']}
Goal: {p['goal']}

Computed:
- Expense Ratio: {p['expense_ratio']} ({p['expense_label']} expense burden)
- Risk Score: {p['risk_score']}
- Risk Type: {p['risk_level']}
- Budget Type: {p['plan_type']}

━━━━━━━━━━━━━━━━━━━━━━━

INSTRUCTIONS:

1. Savings:
   - Use ₹ and %
   - Explain clearly

2. Expenses:
   - Use expense ratio
   - Classify as low/moderate/high

3. Age:
   - Use age {p['age']}
   - Explain investment horizon

4. Risk:
   - Explain classification

━━━━━━━━━━━━━━━━━━━━━━━

ADVICE RULES (STRICT):

- MUST include:
  • Allocation percentages (Equity vs Debt)
  • Specific instruments (index funds, SIP, bonds, PPF)

- DO NOT give generic advice

- Use KNOWLEDGE context

━━━━━━━━━━━━━━━━━━━━━━━

FORMAT:

STEP-BY-STEP REASONING:
Step 1 -
Step 2 -
Step 3 -
Step 4 -
Step 5 -

PERSONALIZED ADVICE:

Investment Strategy:
- Equity: __%
- Debt: __%

Instruments:
- ...
- ...

Action Steps:
- ...
- ...

KEY INSIGHT:
One clear sentence.
"""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=700
    )

    return response.choices[0].message.content


# ── Pipeline ─────────────────────────────────────────────
def run_pipeline(
    income, expenses, age, goal, emi,
    index, texts, sources, model, groq_client
):
    profile = profile_agent(income, expenses, age, goal, emi)
    profile = risk_agent(profile)
    profile = retrieval_agent(profile, index, texts, sources, model)
    advice = reasoning_agent(profile, groq_client)

    return profile, advice