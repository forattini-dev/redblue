#!/usr/bin/env python3
"""
Build the docs index consumed by the MCP `rb.search-docs` tool.

Output: src/mcp/data/docs-index.json
Contents: per-chunk { id, path, title, section, category, keywords, content }.
No vectors. Ranking at runtime is Jaccard over keyword tokens in
src/mcp/search.rs. This script has zero third-party dependencies —
stdlib only.
"""

import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

DOCS_DIR = Path("docs")
OUTPUT_FILE = Path("src/mcp/data/docs-index.json")
MAX_CHUNK_SIZE = 2000
INCLUDE_README = True


def extract_title(content: str, filepath: Path) -> str:
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if match:
        return match.group(1).strip()

    if content.startswith('---'):
        end = content.find('---', 3)
        if end != -1:
            frontmatter = content[3:end]
            match = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', frontmatter, re.MULTILINE)
            if match:
                return match.group(1).strip()

    return filepath.stem.replace('-', ' ').replace('_', ' ').title()


def extract_keywords(content: str) -> list[str]:
    keywords = set()

    for match in re.finditer(r'^#{2,3}\s+(.+)$', content, re.MULTILINE):
        words = match.group(1).lower().split()
        keywords.update(w for w in words if len(w) > 2)

    for match in re.finditer(r'`([^`]+)`', content):
        code = match.group(1).strip()
        if 2 < len(code) < 50:
            keywords.add(code.lower())

    for match in re.finditer(r'\*\*([^*]+)\*\*', content):
        words = match.group(1).lower().split()
        keywords.update(w for w in words if len(w) > 2)

    return sorted(keywords)[:20]


def extract_category(filepath: Path) -> str:
    parts = filepath.parts
    if 'docs' in parts:
        idx = parts.index('docs')
        if idx + 1 < len(parts) - 1:
            return parts[idx + 1]
    return "general"


def clean_content(content: str) -> str:
    content = re.sub(r'```[\s\S]*?```', '[code]', content)
    content = re.sub(r'`([^`]+)`', r'\1', content)
    content = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', content)
    content = re.sub(r'!\[([^\]]*)\]\([^)]+\)', '', content)
    content = re.sub(r'<[^>]+>', '', content)
    content = re.sub(r'\n{3,}', '\n\n', content)
    content = re.sub(r' {2,}', ' ', content)
    return content.strip()


def chunk_document(content: str) -> list[dict]:
    sections = re.split(r'^##\s+', content, flags=re.MULTILINE)

    if len(sections) <= 1 or len(content) <= MAX_CHUNK_SIZE:
        return [{"section": None, "content": content[:MAX_CHUNK_SIZE]}]

    chunks = []
    if sections[0].strip():
        chunks.append({"section": "Overview", "content": sections[0].strip()[:MAX_CHUNK_SIZE]})

    for section in sections[1:]:
        lines = section.split('\n', 1)
        section_title = lines[0].strip()
        section_content = lines[1] if len(lines) > 1 else ""
        chunks.append({
            "section": section_title,
            "content": section_content.strip()[:MAX_CHUNK_SIZE],
        })

    return chunks


SKIP_PATTERNS = (
    'reference_implementations/', 'rust-openssl/', 'recker/', 'quinn/',
    'h3/', 'h3-quinn/', 'reqwest/', 'ureq/', 'undici/', 'quiche/',
    'rustls/', 'tls-parser/', 'ombrac/',
)


def collect_documents() -> list[dict]:
    documents = []

    if DOCS_DIR.exists():
        for md_file in DOCS_DIR.rglob("*.md"):
            try:
                rel_path = md_file.relative_to(Path.cwd())
            except ValueError:
                rel_path = md_file
            path_str = str(rel_path)

            if any(p in path_str for p in SKIP_PATTERNS):
                continue

            try:
                content = md_file.read_text(encoding='utf-8')
                if len(content.strip()) < 50:
                    continue
                documents.append({"path": path_str, "content": content})
            except Exception as e:
                print(f"Warning: Could not read {md_file}: {e}", file=sys.stderr)

    if INCLUDE_README:
        readme = Path("README.md")
        if readme.exists():
            try:
                documents.append({"path": "README.md", "content": readme.read_text(encoding='utf-8')})
            except Exception as e:
                print(f"Warning: Could not read README.md: {e}", file=sys.stderr)

    claude_md = Path("CLAUDE.md")
    if claude_md.exists():
        try:
            documents.append({"path": "CLAUDE.md", "content": claude_md.read_text(encoding='utf-8')})
        except Exception as e:
            print(f"Warning: Could not read CLAUDE.md: {e}", file=sys.stderr)

    return documents


def main():
    print("Building docs index for redblue documentation (keyword-only, no vectors)...")

    raw_docs = collect_documents()
    print(f"Found {len(raw_docs)} documents")

    if not raw_docs:
        print("No documents found!", file=sys.stderr)
        sys.exit(1)

    processed_docs = []
    for doc in raw_docs:
        filepath = Path(doc["path"])
        content = doc["content"]

        title = extract_title(content, filepath)
        keywords = extract_keywords(content)
        category = extract_category(filepath)
        cleaned = clean_content(content)

        for chunk in chunk_document(cleaned):
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

    output = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "document_count": len(processed_docs),
        "documents": processed_docs,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {OUTPUT_FILE} ({OUTPUT_FILE.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
