import re
import chromadb
from sentence_transformers import SentenceTransformer

# Singleton embedding model
_model = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def _get_collection() -> chromadb.Collection:
    client = chromadb.PersistentClient(path="./chroma_db")
    return client.get_or_create_collection("ctf_writeups")


# ChromaDB cosine distance where distance = 1 - cos_sim (range [0, 2]).
# 1.3 was dangerously permissive (cos_sim ≈ -0.3 — noise).
# 1.0 means cos_sim ≥ 0 — loosely related; BM25 re-ranking handles the rest.
SIMILARITY_THRESHOLD = 1.0

# How many candidates to fetch from ChromaDB before BM25 re-ranking.
# Larger = better recall for technical terms that embed poorly (hex addresses,
# acronyms like "ret2csu", "SSTI", "RSA-CRT"); smaller = faster.
_BM25_CANDIDATE_MULTIPLIER = 8


# ---------------------------------------------------------------------------
# Query preprocessing: extract key technical terms
# ---------------------------------------------------------------------------

# CTF-specific token patterns worth preserving verbatim in the BM25 query
_CTF_TERM_RE = re.compile(
    r"""
    \b(?:
      ret2\w+         |   # ret2libc, ret2csu, ret2win, ret2dl
      rop\b           |   # ROP
      srop\b          |   # SROP
      fsop\b          |   # FSOP
      got\b           |   # GOT
      plt\b           |   # PLT
      tcache\b        |   # tcache
      libc\b          |   # libc
      glibc\b         |
      canary\b        |
      pie\b           |   # PIE
      aslr\b          |   # ASLR
      nx\b            |   # NX
      ssp\b           |
      rsa\b           |   # RSA
      ecc\b           |   # ECC
      aes\b           |   # AES
      xor\b           |   # XOR
      base64\b        |
      vigenere\b      |
      wiener\b        |
      sha\d*\b        |   # SHA1, SHA256
      md5\b           |
      ssti\b          |   # SSTI
      sqli\b          |   # SQLi
      xxe\b           |   # XXE
      ssrf\b          |   # SSRF
      lfi\b           |   # LFI
      rfi\b           |   # RFI
      jwt\b           |   # JWT
      oauth\b         |
      heap\b          |
      overflow\b      |
      format.?string\b|
      angr\b          |
      z3\b
    )\b
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _extract_query_terms(text: str) -> str:
    """
    For long challenge descriptions, extract the most signal-dense fragment:
    - any CTF-specific terms (ret2csu, SSTI, RSA, etc.)
    - the first 120 chars (often contains the challenge title/type)
    - the last 80 chars (often contains the flag format hint)

    Combining these avoids embedding dilution when the full text is 500+ chars.
    """
    if len(text) <= 250:
        return text

    ctf_terms = " ".join(_CTF_TERM_RE.findall(text))
    prefix = text[:120]
    suffix = text[-80:]
    return f"{prefix} {ctf_terms} {suffix}".strip()


# ---------------------------------------------------------------------------
# BM25 re-ranking
# ---------------------------------------------------------------------------


def _bm25_rerank(query: str, candidates: list[dict], top_k: int) -> list[dict]:
    """
    Re-rank *candidates* using BM25 on the query tokens.

    Why: all-MiniLM-L6-v2 is a general English model.  Technical CTF terms
    like "ret2csu", "Franklin-Reiter", "tcache poison", or "RSA wiener" may
    have poor cosine similarity against their own writeup because the model
    never saw them during pre-training.  BM25 is token-exact, so it rescues
    these cases and pushes exact keyword matches to the top.

    Weighting: title and key_insight are repeated 3× in the corpus doc so
    they receive higher BM25 term frequency than the raw solution text.

    Final score:
        combined = 0.6 * bm25_norm + 0.4 * (1 - distance_norm)
    """
    try:
        from rank_bm25 import BM25Okapi
    except ImportError:
        return candidates[:top_k]

    if not candidates:
        return []

    def _tok(text: str) -> list[str]:
        return re.findall(r"[a-z0-9]+", text.lower())

    corpus_docs = []
    for c in candidates:
        # Boost title + key_insight (3× repetition = higher TF weight)
        title_rep = (c.get("title", "") + " ") * 3
        insight_rep = (c.get("key_insight", "") + " ") * 3
        tags_rep = (c.get("tags", "") + " ") * 2
        # Use more of the solution for better BM25 recall
        solution_chunk = c.get("solution", "")[:3000]
        corpus_docs.append(
            f"{title_rep}{insight_rep}{tags_rep}"
            f"{c.get('category', '')} {solution_chunk}"
        )

    tokenised_corpus = [_tok(d) for d in corpus_docs]
    bm25 = BM25Okapi(tokenised_corpus)
    bm25_scores = bm25.get_scores(_tok(query))

    max_bm25 = max(bm25_scores) if max(bm25_scores) > 0 else 1.0
    bm25_norm = [s / max_bm25 for s in bm25_scores]

    distances = [c.get("distance", 1.0) for c in candidates]
    max_dist = max(distances) if distances else 1.0
    dist_norm = [d / max_dist for d in distances]

    scored = [
        (0.6 * bm25_norm[i] + 0.4 * (1.0 - dist_norm[i]), i)
        for i in range(len(candidates))
    ]
    scored.sort(reverse=True)

    return [candidates[i] for _, i in scored[:top_k]]


# ---------------------------------------------------------------------------
# Main retrieval functions
# ---------------------------------------------------------------------------


def retrieve(
    query: str,
    category: str = None,
    top_k: int = 3,
    max_distance: float = SIMILARITY_THRESHOLD,
    exclude_terms: str = None,
) -> list[dict]:
    """
    Embed the query, fetch a larger candidate set from ChromaDB, then
    re-rank with BM25 to rescue technical terms that embed poorly.

    Long queries are preprocessed to extract the most signal-dense fragment
    before embedding — avoids dilution from boilerplate challenge text.

    Results with distance > max_distance are dropped before re-ranking.
    """
    model = _get_model()
    collection = _get_collection()

    if collection.count() == 0:
        return []

    # Preprocess: extract key terms for embedding (avoids dilution)
    embed_query = _extract_query_terms(query)
    query_embedding = model.encode(embed_query).tolist()

    n_candidates = min(top_k * _BM25_CANDIDATE_MULTIPLIER, collection.count())

    query_kwargs: dict = {
        "query_embeddings": [query_embedding],
        "n_results": n_candidates,
        "include": ["metadatas", "distances", "documents"],
    }
    if category:
        query_kwargs["where"] = {"category": category}

    results = collection.query(**query_kwargs)

    if not results["ids"] or not results["ids"][0]:
        return []

    retrieved = []
    seen_ids: set[str] = set()
    for i, doc_id in enumerate(results["ids"][0]):
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)

        distance = results["distances"][0][i]
        if distance > max_distance:
            continue

        meta = results["metadatas"][0][i]
        if exclude_terms and exclude_terms.lower() in meta.get("solution", "").lower():
            continue

        retrieved.append({
            "title": meta.get("title", "Unknown"),
            "category": meta.get("category", "misc"),
            "tools": meta.get("tools", ""),
            "solution": meta.get("solution", ""),
            "key_insight": meta.get("key_insight", ""),
            "tags": meta.get("tags", ""),
            "event": meta.get("event", ""),
            "distance": distance,
        })

    # BM25 re-rank using the *original* full query for better term matching
    return _bm25_rerank(query, retrieved, top_k)


def retrieve_multi(
    queries: list[str],
    category: str = None,
    top_k: int = 3,
    max_distance: float = SIMILARITY_THRESHOLD,
) -> list[dict]:
    """
    Run multiple query variants and merge results, deduplicating by title.
    Useful when a challenge can be described several ways (e.g. "RSA Wiener"
    vs "continued fractions" vs "weak private exponent").

    Returns up to top_k results ranked by the best score seen across all queries.
    """
    model = _get_model()
    collection = _get_collection()

    if collection.count() == 0:
        return []

    n_candidates = min(top_k * _BM25_CANDIDATE_MULTIPLIER, collection.count())
    seen: dict[str, dict] = {}  # title -> best result

    for query in queries:
        embed_query = _extract_query_terms(query)
        query_embedding = model.encode(embed_query).tolist()

        query_kwargs: dict = {
            "query_embeddings": [query_embedding],
            "n_results": n_candidates,
            "include": ["metadatas", "distances", "documents"],
        }
        if category:
            query_kwargs["where"] = {"category": category}

        results = collection.query(**query_kwargs)
        if not results["ids"] or not results["ids"][0]:
            continue

        for i, _doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i]
            if distance > max_distance:
                continue
            meta = results["metadatas"][0][i]
            title = meta.get("title", "Unknown")
            if title not in seen or distance < seen[title]["distance"]:
                seen[title] = {
                    "title": title,
                    "category": meta.get("category", "misc"),
                    "tools": meta.get("tools", ""),
                    "solution": meta.get("solution", ""),
                    "key_insight": meta.get("key_insight", ""),
                    "tags": meta.get("tags", ""),
                    "event": meta.get("event", ""),
                    "distance": distance,
                }

    candidates = list(seen.values())
    return _bm25_rerank(queries[0], candidates, top_k)


def retrieve_techniques(
    query: str, category: str = None, top_k: int = 2
) -> list[dict]:
    """
    Query the ctf_techniques collection for abstract technique matches.
    """
    model = _get_model()
    try:
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_or_create_collection("ctf_techniques")
    except Exception:
        return []

    if collection.count() == 0:
        return []

    embed_query = _extract_query_terms(query)
    query_embedding = model.encode(embed_query).tolist()
    query_kwargs: dict = {
        "query_embeddings": [query_embedding],
        "n_results": min(top_k * 3, collection.count()),
        "include": ["metadatas", "distances"],
    }
    if category:
        query_kwargs["where"] = {"category": category}

    results = collection.query(**query_kwargs)
    if not results["ids"] or not results["ids"][0]:
        return []

    retrieved = []
    for i, _doc_id in enumerate(results["ids"][0]):
        distance = results["distances"][0][i]
        if distance > SIMILARITY_THRESHOLD:
            continue
        meta = results["metadatas"][0][i]
        retrieved.append({
            "technique_name": meta.get("technique_name", "unknown"),
            "category": meta.get("category", category or "misc"),
            "recognition": meta.get("recognition", ""),
            "steps": meta.get("steps", ""),
            "reusable_code": meta.get("reusable_code", ""),
            "caveats": meta.get("caveats", ""),
            "novelty": meta.get("novelty", "common"),
            "distance": distance,
        })
    return retrieved[:top_k]
