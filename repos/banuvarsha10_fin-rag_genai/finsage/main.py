"""
main.py — Terminal entry point
Run: python main.py
"""

import os
from groq import Groq
from rag import build_index
from agents import run_pipeline
from evaluate import run_evaluation

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "your-groq-key-here")


def main():
    print("\n" + "="*50)
    print("   FINSAGE — AI FINANCIAL ADVISOR")
    print("="*50)

    # Build knowledge base
    print("\n[Setup] Building knowledge base...")
    index, all_texts, all_sources, model = build_index(pdf_folder="content")
    groq_client = Groq(api_key=GROQ_API_KEY)

    while True:
        print("\nOptions:")
        print("  1. Get financial advice")
        print("  2. Run evaluation (Phase 9)")
        print("  3. Exit")
        choice = input("\nEnter choice (1/2/3): ").strip()

        if choice == "1":
            print("\nEnter your financial profile:")
            income   = int(input("Monthly Income (₹): "))
            expenses = int(input("Monthly Expenses (₹): "))
            emi      = int(input("Monthly EMI (₹, 0 if none): "))
            age      = int(input("Age: "))
            goal     = input("Goal (investment/saving/emergency fund etc): ")

            profile, advice = run_pipeline(
                income,
                expenses,
                age,
                goal,
                emi,
                index,
                all_texts,
                all_sources,
                model,
                groq_client
            )

            print("\n" + "="*50)
            print("   FINAL ADVICE")
            print("="*50)
            print(advice)

        elif choice == "2":
            print("\nRunning evaluation across test cases...")
            run_evaluation(
                groq_client,
                index,
                all_texts,
                all_sources,
                model
            )

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()