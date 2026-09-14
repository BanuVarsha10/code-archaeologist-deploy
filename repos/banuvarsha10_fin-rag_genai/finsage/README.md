# FinSage — Explainable AI Financial Advisor

> Rule-Grounded RAG · Agentic Workflow · Transparent Reasoning

## Project Structure

```
finsage/
├── app.py            ← Streamlit web UI
├── agents.py         ← 4 agentic pipeline agents
├── rag.py            ← FAISS knowledge base + search
├── evaluate.py       ← Phase 9 evaluation
├── main.py           ← Terminal entry point
├── requirements.txt  ← Dependencies
└── *.pdf             ← Your RBI/financial PDFs (place here)
```

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Place your PDF files in this folder

# 3. Run the web app
streamlit run app.py

# OR run in terminal
python main.py
```

## Pipeline

```
User Input
    ↓
Profile Agent   → builds financial profile
    ↓
Risk Agent      → computes risk score + 50-30-20 allocation
    ↓
Retrieval Agent → FAISS search over RBI docs + rules
    ↓
Reasoning Agent → LLM generates step-by-step explainable advice
```

## API Key

Enter your Groq API key in the sidebar of the Streamlit app.
Get a free key at: https://console.groq.com

## Evaluation

Run `python main.py` → Option 2 to compare:
- LLM Only (no RAG)
- RAG Only (no rules/agents)
- Full Pipeline (RAG + Rules + Agents)
