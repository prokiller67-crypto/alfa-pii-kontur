"""Create a source-only submission archive and verify no local secrets entered it."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

root = Path(__file__).resolve().parents[1]
out = root / "artifacts/alfa-pii-source.zip"
out.parent.mkdir(exist_ok=True)
files = [root / p for p in ("README.md", "pyproject.toml", "uv.lock", "Dockerfile", "compose.yaml", ".dockerignore", ".gitignore", "app.py", "vercel.json", ".vercelignore")]
for directory, extensions in {"src": {".py", ".html"}, "tests": {".py"}, "scripts": {".py"},
                              "benchmarks": {".py"}, "config": {".json"}, "docs": {".md", ".yaml"},
                              "migrations": {".sql"}}.items():
    files += [p for p in (root / directory).rglob("*") if p.is_file() and p.suffix in extensions]
with ZipFile(out, "w", ZIP_DEFLATED) as archive:
    for path in sorted(set(files)):
        archive.write(path, path.relative_to(root))
with ZipFile(out) as archive:
    contents = b"\n".join(archive.read(name) for name in archive.namelist())
    if any(any(part in {".venv", ".git", "__pycache__", ".env", "node_modules"}
               for part in Path(name).parts) for name in archive.namelist()):
        raise ValueError("forbidden path found in archive")
    for env in root.glob(".env*"):
        if not env.is_file():
            continue
        for line in env.read_text().splitlines():
            name, _, value = line.partition("=")
            value = value.strip().strip("\"'")
            if any(part in name for part in ("KEY", "TOKEN", "SECRET", "PASSWORD", "REDIS_URL", "DATABASE_URL", "POSTGRES_URL")) and len(value) > 20:
                if value.encode() in contents:
                    raise ValueError("local key found in archive")
    print(f"Source archive verified: {len(archive.namelist())} files, {out.stat().st_size} bytes; no local keys.")
