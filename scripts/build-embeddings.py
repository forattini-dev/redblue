#!/usr/bin/env python3
"""
Build embeddings for redblue documentation.

This script generates embeddings.json from all markdown files in docs/
using the BGE-small-en-v1.5 model via fastembed.

Usage:
    pip install fastembed
    python scripts/build-embeddings.py

Output:
    src/mcp/data/embeddings.json
"""

import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

# Configuration
DOCS_DIR = Path("docs")
OUTPUT_FILE = Path("src/mcp/data/embeddings.json")
MODEL_NAME = "BAAI/bge-small-en-v1.5"
DIMENSIONS = 384
MAX_CHUNK_SIZE = 2000  # characters per chunk
INCLUDE_README = True


def extract_title(content: str, filepath: Path) -> str:
    """Extract title from markdown content."""
    # Try H1 header first
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if match:
        return match.group(1).strip()

    # Try frontmatter title
    if content.startswith('---'):
        end = content.find('---', 3)
        if end != -1:
            frontmatter = content[3:end]
            match = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', frontmatter, re.MULTILINE)
            if match:
                return match.group(1).strip()

    # Fallback to filename
    return filepath.stem.replace('-', ' ').replace('_', ' ').title()


def extract_keywords(content: str) -> list[str]:
    """Extract keywords from markdown content."""
    keywords = set()

    # Headers (H2, H3)
    for match in re.finditer(r'^#{2,3}\s+(.+)$', content, re.MULTILINE):
        words = match.group(1).lower().split()
        keywords.update(w for w in words if len(w) > 2)

    # Inline code
    for match in re.finditer(r'`([^`]+)`', content):
        code = match.group(1).strip()
        if len(code) > 2 and len(code) < 50:
            keywords.add(code.lower())

    # Bold text
    for match in re.finditer(r'\*\*([^*]+)\*\*', content):
        words = match.group(1).lower().split()
        keywords.update(w for w in words if len(w) > 2)

    return sorted(list(keywords))[:20]  # Limit to 20 keywords


def extract_category(filepath: Path) -> str:
    """Extract category from file path."""
    parts = filepath.parts
    if 'docs' in parts:
        idx = parts.index('docs')
        if idx + 1 < len(parts) - 1:
            return parts[idx + 1]
    return "general"


def clean_content(content: str) -> str:
    """Clean markdown content for embedding."""
    # Remove code blocks (keep just a marker)
    content = re.sub(r'```[\s\S]*?```', '[code]', content)

    # Remove inline code backticks
    content = re.sub(r'`([^`]+)`', r'\1', content)

    # Remove links but keep text
    content = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', content)

    # Remove images
    content = re.sub(r'!\[([^\]]*)\]\([^)]+\)', '', content)

    # Remove HTML tags
    content = re.sub(r'<[^>]+>', '', content)

    # Normalize whitespace
    content = re.sub(r'\n{3,}', '\n\n', content)
    content = re.sub(r' {2,}', ' ', content)

    return content.strip()


def chunk_document(content: str, filepath: Path, title: str) -> list[dict]:
    """Split document into chunks if too large."""
    chunks = []

    # Try to split by H2 sections
    sections = re.split(r'^##\s+', content, flags=re.MULTILINE)

    if len(sections) <= 1 or len(content) <= MAX_CHUNK_SIZE:
        # Single chunk
        chunks.append({
            "section": None,
            "content": content[:MAX_CHUNK_SIZE]
        })
    else:
        # First chunk is intro (before first H2)
        if sections[0].strip():
            chunks.append({
                "section": "Overview",
                "content": sections[0].strip()[:MAX_CHUNK_SIZE]
            })

        # Each H2 section
        for section in sections[1:]:
            lines = section.split('\n', 1)
            section_title = lines[0].strip()
            section_content = lines[1] if len(lines) > 1 else ""

            chunks.append({
                "section": section_title,
                "content": section_content.strip()[:MAX_CHUNK_SIZE]
            })

    return chunks


def collect_documents() -> list[dict]:
    """Collect all markdown documents."""
    documents = []

    # Collect from docs/
    if DOCS_DIR.exists():
        for md_file in DOCS_DIR.rglob("*.md"):
            # Skip reference implementations and external docs
            try:
                rel_path = md_file.relative_to(Path.cwd())
            except ValueError:
                # If not relative to cwd, use the path as-is
                rel_path = md_file
            path_str = str(rel_path)

            # Skip external/reference docs
            skip_patterns = [
                'reference_implementations/',
                'rust-openssl/',
                'recker/',
                'quinn/',
                'h3/',
                'h3-quinn/',
                'reqwest/',
                'ureq/',
                'undici/',
                'quiche/',
                'rustls/',
                'tls-parser/',
                'ombrac/',
            ]

            if any(p in path_str for p in skip_patterns):
                continue

            try:
                content = md_file.read_text(encoding='utf-8')
                if len(content.strip()) < 50:  # Skip nearly empty files
                    continue

                documents.append({
                    "path": path_str,
                    "content": content,
                })
            except Exception as e:
                print(f"Warning: Could not read {md_file}: {e}", file=sys.stderr)

    # Include README.md
    if INCLUDE_README:
        readme = Path("README.md")
        if readme.exists():
            try:
                content = readme.read_text(encoding='utf-8')
                documents.append({
                    "path": "README.md",
                    "content": content,
                })
            except Exception as e:
                print(f"Warning: Could not read README.md: {e}", file=sys.stderr)

    # Include CLAUDE.md
    claude_md = Path("CLAUDE.md")
    if claude_md.exists():
        try:
            content = claude_md.read_text(encoding='utf-8')
            documents.append({
                "path": "CLAUDE.md",
                "content": content,
            })
        except Exception as e:
            print(f"Warning: Could not read CLAUDE.md: {e}", file=sys.stderr)

    return documents


def main():
    print(f"Building embeddings for redblue documentation...")
    print(f"Model: {MODEL_NAME}")

    # Collect documents
    raw_docs = collect_documents()
    print(f"Found {len(raw_docs)} documents")

    if not raw_docs:
        print("No documents found!", file=sys.stderr)
        sys.exit(1)

    # Process documents into chunks
    processed_docs = []
    for doc in raw_docs:
        filepath = Path(doc["path"])
        content = doc["content"]

        title = extract_title(content, filepath)
        keywords = extract_keywords(content)
        category = extract_category(filepath)
        cleaned = clean_content(content)

        chunks = chunk_document(cleaned, filepath, title)

        for i, chunk in enumerate(chunks):
            doc_id = f"doc-{len(processed_docs)}"
            processed_docs.append({
                "id": doc_id,
                "path": doc["path"],
                "title": title,
                "section": chunk["section"],
                "category": category,
                "keywords": keywords,
                "content": chunk["content"],
                "parent_path": doc["path"] if chunk["section"] else None,
            })

    print(f"Created {len(processed_docs)} document chunks")

    # Try to generate embeddings
    vectors_generated = False
    try:
        from fastembed import TextEmbedding

        print(f"Initializing embedding model...")
        model = TextEmbedding(MODEL_NAME)

        # Prepare texts for embedding (BGE models need "passage: " prefix)
        texts = []
        for doc in processed_docs:
            text_parts = [doc["title"]]
            if doc["section"]:
                text_parts.append(doc["section"])
            text_parts.append(doc["content"][:1500])  # Limit content size

            full_text = " ".join(text_parts)
            texts.append(f"passage: {full_text}")

        print(f"Generating embeddings for {len(texts)} chunks...")
        embeddings = list(model.embed(texts))

        for i, doc in enumerate(processed_docs):
            doc["vector"] = embeddings[i].tolist()

        vectors_generated = True
        print(f"Generated {len(embeddings)} embeddings")

    except ImportError:
        print("Warning: fastembed not installed. Creating embeddings file without vectors.", file=sys.stderr)
        print("Install with: pip install fastembed", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Could not generate embeddings: {e}", file=sys.stderr)

    # Build output
    output = {
        "version": "1.0",
        "model": MODEL_NAME if vectors_generated else None,
        "dimensions": DIMENSIONS if vectors_generated else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "document_count": len(processed_docs),
        "has_vectors": vectors_generated,
        "documents": processed_docs,
    }

    # Write output
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    file_size = OUTPUT_FILE.stat().st_size
    print(f"Wrote {OUTPUT_FILE} ({file_size:,} bytes)")

    if vectors_generated:
        print(f"Embeddings ready for semantic search!")
    else:
        print(f"Embeddings file created without vectors (fuzzy-only mode)")


if __name__ == "__main__":
    main()
