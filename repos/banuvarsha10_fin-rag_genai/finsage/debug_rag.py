"""
debug_rag.py — RAG Debugging Script
Run: python debug_rag.py
"""

from rag import build_index, search

def main():

    print("="*50)
    print("RAG DEBUG TOOL")
    print("="*50)

    # Build index
    print("\nBuilding index...")
    index, all_texts, all_sources, model = build_index(pdf_folder="content")

    print("\nTotal documents:", len(all_texts))

    # Show sample chunks
    print("\nSample chunks:\n")

    for i in range(5):
        print("="*50)
        print("Source:", all_sources[i])
        print("Text:", all_texts[i][:300])
        print()

    # Interactive search
    while True:

        print("\nEnter query (or type 'exit'):")
        query = input("> ")

        if query.lower() == "exit":
            break

        results = search(
            query,
            index,
            all_texts,
            all_sources,
            model,
            k=5
        )

        print("\nTop Results:\n")

        for i, r in enumerate(results):
            print("="*50)
            print(f"Result {i+1}")
            print("Source:", r["source"])
            print("Distance:", r["distance"])
            print("Text:", r["text"][:300])
            print()

if __name__ == "__main__":
    main()