# Benchmarks

This directory hosts manual comparison scripts between RedBlue commands and well-known security tools. These scripts are **not** automated tests; they help us track progress and performance gaps during development.

## Safety Checklist
- ✅ Run only against hosts you own or have explicit permission to scan.
- ✅ Ensure required tools (e.g., `nmap`) are installed in the environment.
- ✅ Default targets should be safe (`127.0.0.1` or lab services). Always get consent before probing external systems.
- ✅ Mind the rate: RedBlue can run many threads; adjust via flags/config.

## Layout
```
benchmarks/
├── README.md          # This guide
├── .gitignore         # Ignore generated artifacts
├── results/           # Output directory (ignored)
└── nmap_vs_rb.sh      # Comparison script (to be added)
```

Generated outputs must stay under `results/` (ignored by git). Keep raw tool output for transparency.

## Usage Philosophy
- Reproducibility: scripts accept environment variables/arguments rather than hard-coded targets.
- Transparency: capture both tools' outputs side-by-side.
- Documentation: annotate results (latency, differences) in separate markdown notes if needed.

## Roadmap
1. `nmap_vs_rb.sh` – compare port scan presets (current task).
2. `masscan_vs_rb.sh` – evaluate fast-mode throughput.
3. `dig_vs_rb.sh` – validate DNS lookup coverage.
4. `whatweb_vs_rb.sh` – compare tech fingerprinting.

Feel free to add new scripts following the same pattern. Update this README as coverage grows.

### `nmap_vs_rb.sh`

Compare `nmap` with `rb network ports scan`.

```bash
HOST=192.168.0.10 \
NMAP_PRESET=top100 \
RB_PRESET=common \
OUTPUT_DIR=tests/benchmarks/results \
tests/benchmarks/nmap_vs_rb.sh
```

Environment variables:
- `HOST` – target host (default `127.0.0.1`).
- `NMAP_PRESET` – `top100` (default), `full`, or `custom` (requires `NMAP_PORTS`).
- `RB_PRESET` – RedBlue preset (`common`, `full`, `web`).
- `RB_THREADS` / `RB_TIMEOUT` – override threads/timeout; defaults mirror CLI defaults.
- `OUTPUT_DIR` – directory for saved outputs (default `tests/benchmarks/results`).

Outputs:
- Raw `nmap` and `rb` results (`*.txt`).
- Summary with durations and presets used.

> ⚠️ Respect legal/ethical rules; obtain explicit authorization before scanning. Keep thread counts reasonable on shared infrastructure.

### `run_port_benchmark.sh`

Wrapper that resolves a domain (via `rb dns`) and then executes `nmap_vs_rb.sh`.

```bash
./tests/benchmarks/run_port_benchmark.sh tetis.io
autos: HOST resolved via rb (if available), Nmap preset `top100`, RB preset `common`.
```

Arguments:
1. Target domain/IP (required)
2. Nmap preset (optional) – `top100`, `full`, or `custom`.
3. RB preset (optional) – `common`, `full`, `web`.

Environment overrides:
- `RB_THREADS`, `RB_TIMEOUT`, `OUTPUT_DIR`, `NMAP_PRESET`, `RB_PRESET`.

The script prepends `target/release` to the PATH so a locally built `rb` is used when not globally installed.

