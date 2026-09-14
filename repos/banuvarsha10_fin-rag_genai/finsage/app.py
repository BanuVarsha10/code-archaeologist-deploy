"""
app.py — Final Fixed UI (with structured reasoning view)
"""

import streamlit as st
from groq import Groq
from rag import build_index
from agents import run_pipeline


st.set_page_config(page_title="FinSage", page_icon="💰", layout="wide")


@st.cache_resource
def load_knowledge_base():
    return build_index(pdf_folder="content")


# ── Parse LLM Output ──────────────────────────────────────
def parse_output(text):
    sections = {"steps": [], "advice": [], "principle": ""}
    lines = text.split("\n")
    current = None

    for line in lines:
        line = line.strip()

        if "STEP-BY-STEP" in line:
            current = "steps"
        elif "PERSONALIZED ADVICE" in line:
            current = "advice"
        elif "KEY INSIGHT" in line:
            current = "principle"
        elif current == "steps" and line.lower().startswith("step"):
            sections["steps"].append(line)
        elif current == "advice" and line.startswith("-"):
            sections["advice"].append(line[1:].strip())
        elif current == "principle" and line:
            sections["principle"] += line

    return sections


st.title("FinSage — AI Financial Advisor")

# Sidebar
groq_key = st.sidebar.text_input("Groq API Key", type="password")


# Inputs
col1, col2 = st.columns(2)

with col1:
    income = st.number_input("Income (₹)", 1000, 1000000, 20000)
    expenses = st.number_input("Expenses (₹)", 0, 1000000, 8000)
    emi = st.number_input("EMI (₹)", 0, 100000, 0)

with col2:
    age = st.slider("Age", 18, 60, 21)
    goal = st.selectbox("Goal", ["saving", "investment", "retirement", "wealth"])


# ── Run analysis ─────────────────────────────────────────
if st.button("Analyze"):

    if not groq_key:
        st.error("Enter API key")

    else:
        client = Groq(api_key=groq_key)

        index, texts, sources, model = load_knowledge_base()

        profile, advice = run_pipeline(
            income, expenses, age, goal, emi,
            index, texts, sources, model, client
        )

        parsed = parse_output(advice)

        st.success("Analysis Complete")

        # ── Metrics ───────────────────────────────────────
        m1, m2, m3, m4 = st.columns(4)

        m1.metric("Savings", f"₹{profile['monthly_savings']}")
        m2.metric("Savings Rate", f"{profile['savings_rate_pct']}%")
        m3.metric("Risk Tolerance", profile["risk_level"])
        m4.metric("Score", profile["risk_score"])

        st.divider()

        # ── Budget ────────────────────────────────────────
        st.subheader("Budget Breakdown")
        b1, b2, b3 = st.columns(3)

        b1.metric("Needs", f"₹{profile['needs']}")
        b2.metric("Wants", f"₹{profile['wants']}")
        b3.metric("Savings", f"₹{profile['recommended_savings']}")

        st.info(f"Plan: {profile['plan_type']}")

        st.divider()

        # ── Financial Health ──────────────────────────────
        st.subheader("Financial Health")
        st.write("Expense Ratio:", profile["expense_ratio"])

        st.divider()

        # ── 3 Column Explanation ──────────────────────────
        c1, c2, c3 = st.columns(3)

        with c1:
            st.subheader("Step-by-Step Reasoning")
            for step in parsed["steps"]:
                st.markdown(f"""
                <div style='background:#1e293b; padding:10px; border-radius:8px; margin-bottom:8px; color:white'>
                {step}
                </div>
                """, unsafe_allow_html=True)

        with c2:
            st.subheader("Personalized Advice")
            for adv in parsed["advice"]:
                st.markdown(f"""
                <div style='background:#1e2d45; padding:10px; border-radius:8px; margin-bottom:8px; color:white'>
                {adv}
                </div>
                """, unsafe_allow_html=True)

        with c3:
            st.subheader("Key Insight")
            st.info(parsed["principle"])