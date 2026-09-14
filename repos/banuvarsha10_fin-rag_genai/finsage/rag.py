"""
rag.py — Knowledge Base + FAISS Search
Handles PDF loading, chunking, embedding, and retrieval

Research paper fixes applied:
- Source metadata stored at index build time (not keyword guessing at retrieval)
- Distance threshold to filter irrelevant chunks
- Deduplication of near-identical results
- Chunk size documented as empirical choice (300 words)
- Model version noted for reproducibility
"""

import os
import re
import numpy as np
import faiss
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer

# ── Reproducibility settings ───────────────────────────────
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"   # sentence-transformers 2.x
CHUNK_SIZE_WORDS     = 300                    # empirically chosen (see paper §4.2)
MAX_L2_DISTANCE      = 1.5                    # retrieval relevance threshold
DEDUP_SIMILARITY     = 0.95                   # cosine similarity above which a chunk is duplicate

# ── Financial rules knowledge base ────────────────────────
# Each rule is stored as (text, source_label) for clean metadata
RULES = [
    "An emergency fund should cover 3 to 6 months of expenses.",
    "The 50-30-20 rule divides income into needs (50%), wants (30%), and savings (20%).",
    "Avoid high-interest debt whenever possible.",
    "Invest according to risk tolerance and time horizon.",
    "Diversification reduces investment risk.",
    "Track expenses regularly to improve budgeting.",
    "Savings should be prioritized before discretionary spending.",
    "Maintain a balance between liquidity and investment.",
    "EMI payments should not exceed 40% of monthly income.",
    "Start investing early to benefit from compounding interest.",
]


def load_pdfs(pdf_folder="content"):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pdf_folder = os.path.join(base_dir, "..", pdf_folder)

    chunks_with_meta = []
    for fname in os.listdir(pdf_folder):
        if fname.endswith(".pdf"):
            try:
                reader = PdfReader(os.path.join(pdf_folder, fname))
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""
                text = re.sub(r'\s+', ' ', text).strip()
                words = text.split()
                for i in range(0, len(words), CHUNK_SIZE_WORDS):
                    chunk = " ".join(words[i:i + CHUNK_SIZE_WORDS])
                    if len(chunk.split()) > 30:
                        chunks_with_meta.append((chunk, "RBI Document"))

                print(f"  Loaded: {fname} → {len(chunks_with_meta)} chunks so far")

            except Exception as e:
                print(f"  Skipped {fname}: {e}")

    return chunks_with_meta


def build_index(pdf_folder="content", model_name=EMBEDDING_MODEL_NAME):
    """
    Build FAISS index from rules + PDFs.

    Key design decisions (documented for paper reproducibility):
    - Embedding model : all-MiniLM-L6-v2 (sentence-transformers)
    - Index type      : IndexFlatL2 (exact search, no approximation)
    - Chunk size      : 300 words (empirically validated)
    - Source metadata : stored alongside text at build time
    """
    print("[RAG] Loading embedding model...")
    model = SentenceTransformer(model_name)

    print("[RAG] Loading PDFs...")
    pdf_chunks_with_meta = load_pdfs(pdf_folder)

    # Build parallel lists: texts and their source labels
    # Source is assigned here at build time — NOT guessed at retrieval time
    rules_with_meta = [(rule, "Financial Rule") for rule in RULES]
    all_entries      = rules_with_meta + pdf_chunks_with_meta   # list of (text, source)

    all_texts   = [entry[0] for entry in all_entries]
    all_sources = [entry[1] for entry in all_entries]

    print(f"[RAG] Total documents: {len(all_texts)} "
          f"({len(rules_with_meta)} rules + {len(pdf_chunks_with_meta)} PDF chunks)")

    print("[RAG] Generating embeddings...")
    embeddings = model.encode(all_texts, show_progress_bar=True,
                              batch_size=64, normalize_embeddings=True)

    print("[RAG] Building FAISS index (IndexFlatL2)...")
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(np.array(embeddings, dtype="float32"))

    print(f"[RAG] Index ready: {index.ntotal} vectors | dim={embeddings.shape[1]}")
    return index, all_texts, all_sources, model


def cosine_similarity(a, b):
    """Compute cosine similarity between two unit-normalised vectors."""
    return float(np.dot(a, b))


def search(query, index, all_texts, all_sources, model,
           k=5, max_distance=MAX_L2_DISTANCE, dedup_threshold=DEDUP_SIMILARITY):
    """
    Retrieve top-k relevant chunks for a query.

    Improvements over baseline:
    1. Distance threshold  — drops chunks with L2 dist > max_distance
    2. Deduplication       — drops chunks with cosine similarity > dedup_threshold
                             to any already-selected chunk
    3. Source from metadata — returns all_sources[i], not keyword heuristics

    Args:
        query          : natural language query string
        index          : FAISS IndexFlatL2
        all_texts      : list of document strings (parallel to index)
        all_sources    : list of source labels (parallel to all_texts)
        model          : SentenceTransformer instance
        k              : max results to return
        max_distance   : L2 distance cutoff (tune empirically; default 1.5)
        dedup_threshold: cosine similarity above which a result is a duplicate

    Returns:
        list of dicts with keys: text, source, distance
    """
    query_embedding = model.encode([query], normalize_embeddings=True)

    # Retrieve more candidates so filtering still yields k results
    candidates = min(k * 3, index.ntotal)
    distances, indices = index.search(
        np.array(query_embedding, dtype="float32"), candidates
    )

    results          = []
    selected_vectors = []   # for deduplication

    for dist, idx in zip(distances[0], indices[0]):
        if idx == -1:
            continue

        # 1. Distance filter
        if dist > max_distance:
            continue

        # 2. Deduplication — skip if too similar to an already-selected chunk
        chunk_vec = model.encode([all_texts[idx]], normalize_embeddings=True)[0]
        is_duplicate = any(
            cosine_similarity(chunk_vec, sel_vec) >= dedup_threshold
            for sel_vec in selected_vectors
        )
        if is_duplicate:
            continue

        # 3. Source from metadata (reliable, not keyword-based)
        results.append({
            "text"    : all_texts[idx],
            "source"  : all_sources[idx],
            "distance": round(float(dist), 4),
        })
        selected_vectors.append(chunk_vec)

        if len(results) >= k:
            break

    # Fallback: if threshold filtered everything, return closest match anyway
    if not results and index.ntotal > 0:
        fallback_idx = int(indices[0][0])
        results.append({
            "text"    : all_texts[fallback_idx],
            "source"  : all_sources[fallback_idx],
            "distance": round(float(distances[0][0]), 4),
        })

    return results