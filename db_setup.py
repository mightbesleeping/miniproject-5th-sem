"""
db_setup.py — One-shot DuckDB schema initializer.

Run once before starting the engine for the first time:
    uv run python db_setup.py
"""
from edr.db import AlertStore
from edr.utils import load_config


def main() -> None:
    cfg = load_config()
    db_cfg = cfg["edr"]["db"]
    path = db_cfg.get("path", "data/edr_alerts.duckdb")

    print(f"Initializing DuckDB at: {path}")
    with AlertStore(path) as store:
        print("Schema ready.")
        total = store.count()
        print(f"Current alert count: {total}")


if __name__ == "__main__":
    main()
