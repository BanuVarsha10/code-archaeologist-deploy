"""
evaluate.py — Phase 9 Evaluation
Compares: LLM Only vs RAG Only vs Full Pipeline

Research paper fixes applied:
- 6 test cases (was 3) for statistical credibility
- Weighted rubric 0/0.5/1 per criterion (was binary 0/1)
- 6th criterion: actionability of advice
- Fair RAG-only query (matches full pipeline query)
- LLM-as-judge second scoring for inter-rater validation
- Grouped bar chart + per-criterion radar chart
- temperature=0.1 and seed=42 on all LLM calls for reproducibility
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
from groq import Groq
from rag import search
from agents import (profile_agent, risk_agent,
                    retrieval_agent, reasoning_agent)

# ── Reproducibility ────────────────────────────────────────
LLM_MODEL       = "llama-3.3-70b-versatile"
LLM_TEMPERATURE = 0.1     # low temperature → deterministic, reproducible
LLM_SEED        = 42
LLM_MAX_TOKENS  = 400

# ── Test cases (6 cases for statistical credibility) ──────
TEST_CASES = [
    # Original 3
    {"income": 15000, "expenses": 8500,  "age": 21, "goal": "investment",    "emi": 0},
    {"income": 50000, "expenses": 35000, "age": 35, "goal": "saving",        "emi": 5000},
    {"income": 25000, "expenses": 22000, "age": 28, "goal": "emergency fund","emi": 0},
    # Added for paper: edge cases and diversity
    {"income": 100000,"expenses": 40000, "age": 32, "goal": "investment",    "emi": 15000},  # high income, high risk
    {"income": 20000, "expenses": 20000, "age": 24, "goal": "emergency fund","emi": 0},      # zero savings edge case
    {"income": 30000, "expenses": 18000, "age": 19, "goal": "investment",    "emi": 0},      # young, compounding use case

    
    {"income": 80000,"expenses": 78000,"age": 28,"goal": "investment","emi": 0},
]


# ── Shared LLM call helper ─────────────────────────────────
def _llm_call(groq_client, prompt, max_tokens=LLM_MAX_TOKENS):
    """Single point for all LLM calls — reproducibility settings in one place."""
    response = groq_client.chat.completions.create(
        model       = LLM_MODEL,
        messages    = [{"role": "user", "content": prompt}],
        max_tokens  = max_tokens,
        temperature = LLM_TEMPERATURE,
        seed        = LLM_SEED,
    )
    return response.choices[0].message.content


# ── System 1: LLM Only ────────────────────────────────────
def system1_llm_only(profile, groq_client):
    prompt = f"""You are a financial advisor.
User earns ₹{profile['income']} and spends ₹{profile['expenses']} per month.
EMI: ₹{profile.get('emi', 0)}. Age: {profile['age']}. Goal: {profile['goal']}.
Give financial advice."""
    return _llm_call(groq_client, prompt)


# ── System 2: RAG Only ────────────────────────────────────
def system2_rag_only(profile, groq_client, index, all_texts, all_sources, model):
    # FIX: Use same rich query as full pipeline (fair comparison)
    query   = (f"financial advice for {profile['goal']} "
               f"income {profile['income']} age {profile['age']}")
    results = search(query, index, all_texts, all_sources, model, k=3)
    context = "\n".join([r["text"] for r in results])

    prompt = f"""You are a financial advisor.
Using the context below, give the user financial advice.

Context:
{context}

User earns ₹{profile['income']} and spends ₹{profile['expenses']} per month.
EMI: ₹{profile.get('emi', 0)}. Age: {profile['age']}. Goal: {profile['goal']}.
Give financial advice with specific rupee amounts."""
    return _llm_call(groq_client, prompt)


# ── System 3: Full Pipeline ───────────────────────────────
def system3_full_pipeline(profile, groq_client, index, all_texts, all_sources, model):
    import io
    from contextlib import redirect_stdout
    f = io.StringIO()
    with redirect_stdout(f):
        p = profile_agent(profile['income'], profile['expenses'],
                          profile['age'], profile['goal'], profile.get('emi', 0))
        p = risk_agent(p)
        p = retrieval_agent(p, index, all_texts, all_sources, model)
        advice = reasoning_agent(p, groq_client)
    return advice


# ── Weighted scoring rubric (0 / 0.5 / 1 per criterion) ───
"""
Rubric design (documented for paper §5.1):
Each criterion is scored 0 (absent), 0.5 (partial), or 1 (fully met).
Max score = 6.0. Criteria directly map to the paper's claimed contributions.

Criterion 1 — Uses actual rupee numbers
  0   : No numbers at all
  0.5 : Percentage or generic numbers (e.g. "save 20%")
  1   : Specific ₹ amounts matching user's profile

Criterion 2 — Relevant financial terminology
  0   : No financial terms
  0.5 : ≥1 financial term present
  1   : ≥3 financial terms present (budget, invest, EMI, emergency, etc.)

Criterion 3 — Step-by-step structured reasoning
  0   : No steps, plain paragraph
  0.5 : Numbered list but no headers/labels
  1   : Labelled steps with clear structure (Step N - Label: Detail)

Criterion 4 — Cites source or financial rule
  0   : No citation or attribution
  0.5 : Vague reference ("according to best practices")
  1   : Explicit rule/source named (50-30-20, emergency fund rule, RBI, etc.)

Criterion 5 — Personalized to user profile
  0   : Generic advice not linked to user
  0.5 : References goal or age
  1   : References goal AND age AND income/savings amount

Criterion 6 — Actionability of advice
  0   : Vague suggestions only ("save more", "invest wisely")
  0.5 : One concrete action with amount
  1   : ≥2 concrete actions with specific ₹ amounts or %
"""

KEYWORDS_FINANCE = [
    "saving", "budget", "invest", "expense", "emergency",
    "fund", "emi", "liquidity", "compound", "diversif",
    "allocation", "debt", "income", "portfolio",
]

KEYWORDS_RULES = [
    "50-30-20", "50/30/20", "emergency fund", "emi", "rbi",
    "rule", "source", "retrieved", "document", "principle",
    "guideline", "3 to 6", "6 months", "40%", "20%",
]

KEYWORDS_ACTION = [
    "₹", "per month", "monthly", "start", "open", "transfer",
    "allocate", "set aside", "increase", "reduce", "cut",
]


def score_output(output, profile):
    """
    Score a system output on 6 weighted criteria (0/0.5/1 each).
    Returns (total_score: float, breakdown: dict, reasons: list[str])
    Max possible score: 6.0
    """
    breakdown = {}
    reasons   = []
    income_str = str(profile['income'])

    # ── Criterion 1: Actual rupee numbers ─────────────────
    rupee_count = output.count("₹")
    has_income  = income_str in output
    if rupee_count >= 3 or (rupee_count >= 1 and has_income):
        c1 = 1.0
        reasons.append("✅ C1 (1.0) — Uses specific ₹ amounts")
    elif rupee_count >= 1 or "%" in output:
        c1 = 0.5
        reasons.append("⚠️ C1 (0.5) — Partial numbers (% or generic ₹)")
    else:
        c1 = 0.0
        reasons.append("❌ C1 (0.0) — No numerical values")
    breakdown["Actual numbers"] = c1

    # ── Criterion 2: Financial terminology ────────────────
    matched_terms = sum(1 for k in KEYWORDS_FINANCE if k in output.lower())
    if matched_terms >= 3:
        c2 = 1.0
        reasons.append(f"✅ C2 (1.0) — {matched_terms} financial terms present")
    elif matched_terms >= 1:
        c2 = 0.5
        reasons.append(f"⚠️ C2 (0.5) — Only {matched_terms} financial term(s)")
    else:
        c2 = 0.0
        reasons.append("❌ C2 (0.0) — No financial terminology")
    breakdown["Financial terms"] = c2

    # ── Criterion 3: Step-by-step reasoning ───────────────
    has_labelled_steps = (
        "step" in output.lower() and
        any(f"step {i}" in output.lower() for i in range(1, 6))
    )
    has_numbered_list = any(f"{i}." in output for i in range(1, 6))
    if has_labelled_steps:
        c3 = 1.0
        reasons.append("✅ C3 (1.0) — Labelled step-by-step reasoning")
    elif has_numbered_list:
        c3 = 0.5
        reasons.append("⚠️ C3 (0.5) — Numbered list (no step labels)")
    else:
        c3 = 0.0
        reasons.append("❌ C3 (0.0) — No structured reasoning")
    breakdown["Step-by-step"] = c3

    # ── Criterion 4: Cites rule or source ─────────────────
    explicit_cite = any(w in output.lower() for w in [
        "50-30-20", "50/30/20", "emergency fund rule", "rbi", "retrieved",
        "document", "3 to 6 months", "40% of", "financial rule",
    ])
    vague_cite = any(w in output.lower() for w in [
        "rule", "source", "principle", "guideline", "best practice",
        "recommend", "according to",
    ])
    if explicit_cite:
        c4 = 1.0
        reasons.append("✅ C4 (1.0) — Explicitly cites rule/source")
    elif vague_cite:
        c4 = 0.5
        reasons.append("⚠️ C4 (0.5) — Vague reference to rules/principles")
    else:
        c4 = 0.0
        reasons.append("❌ C4 (0.0) — No source or rule citation")
    breakdown["Cites source"] = c4

    # ── Criterion 5: Personalized to user ─────────────────
    has_goal    = profile['goal'].lower() in output.lower()
    has_age     = str(profile['age']) in output
    has_amounts = income_str in output or str(profile['expenses']) in output
    personal_count = sum([has_goal, has_age, has_amounts])
    if personal_count >= 3:
        c5 = 1.0
        reasons.append("✅ C5 (1.0) — Personalized (goal + age + amounts)")
    elif personal_count >= 1:
        c5 = 0.5
        reasons.append(f"⚠️ C5 (0.5) — Partially personalized ({personal_count}/3)")
    else:
        c5 = 0.0
        reasons.append("❌ C5 (0.0) — Generic advice, not personalized")
    breakdown["Personalized"] = c5

    # ── Criterion 6: Actionability ────────────────────────
    action_count = sum(1 for k in KEYWORDS_ACTION if k in output.lower())
    has_two_actions = (
        action_count >= 2 and
        ("₹" in output or "%" in output)
    )
    has_one_action = action_count >= 1
    if has_two_actions:
        c6 = 1.0
        reasons.append("✅ C6 (1.0) — ≥2 concrete actions with amounts")
    elif has_one_action:
        c6 = 0.5
        reasons.append("⚠️ C6 (0.5) — 1 concrete action present")
    else:
        c6 = 0.0
        reasons.append("❌ C6 (0.0) — Vague advice, no concrete actions")
    breakdown["Actionability"] = c6

    total = round(c1 + c2 + c3 + c4 + c5 + c6, 1)
    return total, breakdown, reasons


# ── LLM-as-judge scorer (inter-rater validation) ──────────
LLM_JUDGE_PROMPT = """You are an expert evaluator of financial advisory systems.
Score the following financial advice on a scale of 0-6 using these criteria:
1. Uses actual rupee amounts (0=none, 0.5=partial, 1=specific ₹ values)
2. Uses relevant financial terms (0=none, 0.5=some, 1=3+ terms)
3. Step-by-step reasoning (0=none, 0.5=listed, 1=labelled steps)
4. Cites rules or sources (0=none, 0.5=vague, 1=explicit rule/source)
5. Personalized to user (0=generic, 0.5=partial, 1=goal+age+amounts)
6. Actionability (0=vague, 0.5=1 action, 1=2+ actions with amounts)

User profile: Income ₹{income}, Expenses ₹{expenses}, Age {age}, Goal: {goal}

Advice to evaluate:
{output}

Respond with ONLY a number between 0 and 6 (decimals allowed). Nothing else."""


def llm_judge_score(output, profile, groq_client):
    """Use LLM as a second scorer for inter-rater reliability."""
    prompt = LLM_JUDGE_PROMPT.format(
        income=profile['income'], expenses=profile['expenses'],
        age=profile['age'], goal=profile['goal'], output=output[:800]
    )
    try:
        raw = _llm_call(groq_client, prompt, max_tokens=10).strip()
        return float(raw.split()[0])
    except Exception:
        return None


# ── Run evaluation ────────────────────────────────────────
def run_evaluation(groq_client, index, all_texts, all_sources, model):
    results_table    = []
    criteria_records = []   # for per-criterion analysis

    for i, profile in enumerate(TEST_CASES):
        print(f"\n{'='*60}")
        print(f"TEST CASE {i+1}: ₹{profile['income']} | "
              f"Age {profile['age']} | Goal: {profile['goal']}")
        print(f"{'='*60}")

        out1 = system1_llm_only(profile, groq_client)
        out2 = system2_rag_only(profile, groq_client, index, all_texts, all_sources, model)
        out3 = system3_full_pipeline(profile, groq_client, index, all_texts, all_sources, model)

        s1, bd1, r1 = score_output(out1, profile)
        s2, bd2, r2 = score_output(out2, profile)
        s3, bd3, r3 = score_output(out3, profile)

        # LLM-as-judge for inter-rater validation
        j1 = llm_judge_score(out1, profile, groq_client)
        j2 = llm_judge_score(out2, profile, groq_client)
        j3 = llm_judge_score(out3, profile, groq_client)

        print(f"  Auto scores  → LLM Only: {s1}/6 | RAG Only: {s2}/6 | Full: {s3}/6")
        if all(j is not None for j in [j1, j2, j3]):
            print(f"  Judge scores → LLM Only: {j1}/6 | RAG Only: {j2}/6 | Full: {j3}/6")

        results_table.append({
            "Test Case"           : f"Case {i+1}",
            "Income"              : f"₹{profile['income']}",
            "Age"                 : profile["age"],
            "Goal"                : profile["goal"],
            "LLM Only (/6)"       : s1,
            "RAG Only (/6)"       : s2,
            "Full Pipeline (/6)"  : s3,
            "Judge-LLM (/6)"      : j1,
            "Judge-RAG (/6)"      : j2,
            "Judge-Full (/6)"     : j3,
        })

        # Store per-criterion breakdowns for radar chart
        for criterion, score in bd1.items():
            criteria_records.append({"system": "LLM Only",      "criterion": criterion, "score": score, "case": i+1})
        for criterion, score in bd2.items():
            criteria_records.append({"system": "RAG Only",      "criterion": criterion, "score": score, "case": i+1})
        for criterion, score in bd3.items():
            criteria_records.append({"system": "Full Pipeline",  "criterion": criterion, "score": score, "case": i+1})

    df      = pd.DataFrame(results_table)
    df_crit = pd.DataFrame(criteria_records)

    # Print summary table
    print("\n" + "="*60)
    print("  EVALUATION RESULTS (Weighted Rubric, Max = 6.0)")
    print("="*60)
    print(df[["Test Case", "Income", "Age", "Goal",
              "LLM Only (/6)", "RAG Only (/6)", "Full Pipeline (/6)"]].to_string(index=False))

    print(f"\nAverage Scores (Auto-scored):")
    print(f"  LLM Only     : {df['LLM Only (/6)'].mean():.2f}/6")
    print(f"  RAG Only     : {df['RAG Only (/6)'].mean():.2f}/6")
    print(f"  Full Pipeline: {df['Full Pipeline (/6)'].mean():.2f}/6")

    # Inter-rater correlation
    valid = df.dropna(subset=["Judge-Full (/6)"])
    if len(valid) > 0:
        from scipy.stats import pearsonr
        corr_full, _ = pearsonr(valid["Full Pipeline (/6)"], valid["Judge-Full (/6)"])
        print(f"\nInter-rater reliability (Pearson r, Full Pipeline): {corr_full:.2f}")

    plot_results(df, df_crit)
    return df, df_crit


# ── Plots ─────────────────────────────────────────────────
def plot_results(df, df_crit):
    matplotlib.rcParams['font.family'] = 'DejaVu Sans'
    fig = plt.figure(figsize=(16, 6))

    # ── Plot 1: Grouped bar chart (per test case) ──────────
    ax1 = fig.add_subplot(1, 3, 1)
    cases    = df["Test Case"].tolist()
    x        = np.arange(len(cases))
    width    = 0.25
    colors   = ["#f87171", "#fb923c", "#34d399"]
    systems  = ["LLM Only (/6)", "RAG Only (/6)", "Full Pipeline (/6)"]
    labels   = ["LLM Only", "RAG Only", "Full Pipeline"]

    for j, (col, label, color) in enumerate(zip(systems, labels, colors)):
        bars = ax1.bar(x + j * width, df[col], width,
                       label=label, color=color, edgecolor="white", linewidth=0.8)
        for bar in bars:
            h = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2, h + 0.05,
                     f"{h:.1f}", ha="center", va="bottom", fontsize=7)

    ax1.set_xticks(x + width)
    ax1.set_xticklabels(cases, fontsize=8, rotation=15)
    ax1.set_ylabel("Score (out of 6)", fontsize=9)
    ax1.set_title("Per Test Case Scores", fontsize=10, fontweight="bold")
    ax1.set_ylim(0, 7.2)
    ax1.axhline(y=6, color="gray", linestyle="--", linewidth=0.7, alpha=0.5)
    ax1.legend(fontsize=7)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # ── Plot 2: Average score bar chart ───────────────────
    ax2 = fig.add_subplot(1, 3, 2)
    avg_scores = [df[c].mean() for c in systems]
    system_labels = ["LLM Only", "RAG Only", "Full Pipeline\n(RAG+Rules+Agents)"]
    bars2 = ax2.bar(system_labels, avg_scores, color=colors, width=0.5,
                    edgecolor="white", linewidth=1.2)
    for bar, score in zip(bars2, avg_scores):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                 f"{score:.2f}/6", ha="center", va="bottom",
                 fontsize=11, fontweight="bold")
    ax2.set_ylabel("Average Score (out of 6)", fontsize=9)
    ax2.set_title("Average System Comparison", fontsize=10, fontweight="bold")
    ax2.set_ylim(0, 7.2)
    ax2.axhline(y=6, color="gray", linestyle="--", linewidth=0.7, alpha=0.5)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # ── Plot 3: Per-criterion radar chart ─────────────────
    ax3 = fig.add_subplot(1, 3, 3, polar=True)
    criteria = df_crit["criterion"].unique().tolist()
    N        = len(criteria)
    angles   = [n / float(N) * 2 * np.pi for n in range(N)]
    angles  += angles[:1]   # close the loop

    ax3.set_theta_offset(np.pi / 2)
    ax3.set_theta_direction(-1)
    plt.xticks(angles[:-1], criteria, size=7)
    ax3.set_ylim(0, 1)

    for system, color in zip(["LLM Only", "RAG Only", "Full Pipeline"], colors):
        vals = [
            df_crit[
                (df_crit["system"] == system) &
                (df_crit["criterion"] == c)
            ]["score"].mean()
            for c in criteria
        ]
        vals += vals[:1]
        ax3.plot(angles, vals, linewidth=1.5, linestyle="solid",
                 color=color, label=system)
        ax3.fill(angles, vals, color=color, alpha=0.15)

    ax3.set_title("Per-Criterion Breakdown", fontsize=10,
                  fontweight="bold", pad=15)
    ax3.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=7)

    plt.suptitle("FinSage: System Evaluation Results",
                 fontsize=13, fontweight="bold", y=1.01)
    plt.tight_layout()
    plt.savefig("evaluation_results.png", dpi=150, bbox_inches="tight")
    plt.show()
    print("Graphs saved as evaluation_results.png")