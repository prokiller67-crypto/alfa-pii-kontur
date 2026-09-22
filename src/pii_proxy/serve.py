"""Container entry point; initialize multiprocess metric storage before worker imports."""
import os
from pathlib import Path


def main():
    metrics_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if metrics_dir:
        # /tmp is a fresh container tmpfs on each start, never a shared host folder.
        Path(metrics_dir).mkdir(parents=True, exist_ok=True)
    workers = int(os.environ.get("PII_WORKERS", "4"))
    if not 1 <= workers <= 32:
        raise ValueError("PII_WORKERS_must_be_1_to_32")
    os.execv(".venv/bin/uvicorn", ["uvicorn", "pii_proxy.app:app", "--host", "0.0.0.0", "--port", "8090",
                                 "--workers", str(workers), "--no-access-log", "--no-proxy-headers"])


if __name__ == "__main__":
    main()
