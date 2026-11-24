# TILI v0.2 — TI Log Intelligence

**Application version:** 0.2.0

TILI is a local-first Streamlit tool for reviewing EBK, RZK, TIG and HSM/cHSM/HSK logs.

## Quick start

See [Installation and User Guide](docs/SETUP_AND_CONFIGURATION.md) for Windows, Linux and macOS instructions.

In short:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

On Windows PowerShell, create the environment with `py -m venv .venv`, activate it with `.\\.venv\\Scripts\\Activate.ps1`, then install requirements and run Streamlit.

Open `http://localhost:8501` in your browser.

## Current capabilities

- Upload `.log`, `.txt`, `.csv`, `.json` and `.zip` files.
- Parse common timestamps and extract selected HSK identity details.
- Apply configurable starter diagnostic rules.
- Review findings, evidence, timelines, time-based correlations and instance comparisons.
- Highlight explicit expired-card date evidence in red.
- Export findings to CSV and analysis to JSON.
- Run locally; no external AI service is called.

## Upload limits

Configured in `config/settings.yaml` and `.streamlit/config.toml`:

- `version: 0.2.0`
- `max_upload_mb: 1024`
- `max_zip_members: 1024`

The limits are enforced by the application as well as Streamlit's upload setting. Large files require sufficient RAM and may affect performance.

## Important limitations

TILI is a development tool, not a validated production diagnostic system. Rule matches are investigative evidence, not proof of root cause. Correlation does not establish causality. Card validity is only classified when supported, explicitly labelled expiry information is found in the logs; it is not cryptographic certificate validation.

Use approved, anonymised logs. Review evidence and recommendations against approved product documentation before acting.

## Project structure

- `app.py` — Streamlit interface
- `config/settings.yaml` — application settings
- `.streamlit/config.toml` — Streamlit server upload limit
- `data/knowledge_base.json` — starter diagnostic rules
- `src/tili/` — parsing, ingestion, detection, analysis and reporting modules
- `tests/` — automated tests
- `docs/SETUP_AND_CONFIGURATION.md` — colleague installation and user guide
