# 🛡️ PackagePatrol AI

### Intelligent Supply Chain Security for Open-Source Packages

**The Antivirus for Your Package Manager.**

PackagePatrol AI is a defensive hackathon MVP that helps developers check Python `pip` and JavaScript `npm` packages before installation. It combines real registry metadata, package-name similarity/typosquatting heuristics, OSV vulnerability lookups, transparent risk scoring, and optional AI explanations.

> **Important:** This is not a full malware scanner, antivirus engine, or sandbox. It does not execute package code. A LOW result is not a guarantee of safety.

## Features

- Real PyPI and npm package metadata
- Possible typosquatting detection
- Transparent 0–100 risk score
- LOW / MEDIUM / HIGH risk levels
- OSV known-vulnerability lookup for the selected package version
- Optional Groq AI explanation based only on scan evidence
- Security findings with evidence
- Package comparison for a likely intended package
- SQLite scan history
- Real-data dashboard
- JSON and TXT reports
- Defensive design: no package installation or execution

## Architecture

```text
packagepatrol/
├── app.py
├── analyzer.py
├── package_sources.py
├── risk_engine.py
├── ai_analyzer.py
├── utils.py
├── requirements.txt
├── README.md
├── .gitignore
└── .streamlit/
    └── config.toml
```

### What each file does

- `app.py` — Streamlit UI, pages, history, reports, and scan flow.
- `package_sources.py` — PyPI/npm registry requests and metadata normalization.
- `analyzer.py` — typosquatting heuristics, OSV lookup, and security signals.
- `risk_engine.py` — risk labels and summaries.
- `ai_analyzer.py` — optional Groq explanation.
- `utils.py` — validation and helper functions.

## How it works

1. Select `pip` or `npm`.
2. Enter a package name.
3. PackagePatrol retrieves metadata from the official public registry.
4. It compares the name with popular/known package names.
5. It checks the selected package version against OSV vulnerability data.
6. It evaluates conservative metadata heuristics.
7. It calculates a deterministic risk score.
8. It explains the result and recommends an action.

## Run locally

```bash
git clone YOUR_REPOSITORY_URL
cd packagepatrol
pip install -r requirements.txt
streamlit run app.py
```

## Optional AI setup

The core scanner works without an LLM key. To enable the AI explanation, add a Groq key to Streamlit Secrets.

`.streamlit/secrets.toml` locally:

```toml
GROQ_API_KEY = "your_key_here"
GROQ_MODEL = "openai/gpt-oss-20b"
```

Never commit `secrets.toml`. It is ignored by `.gitignore`.

For Streamlit Cloud, add the same values in **Settings → Secrets**.

## Deployment on Streamlit Cloud

1. Push this project to a public GitHub repository.
2. Open Streamlit Community Cloud.
3. Create a new app from the repository.
4. Select `app.py` as the main file.
5. Deploy.
6. If you want AI explanations, add `GROQ_API_KEY` and `GROQ_MODEL` in the app Secrets.

The scanner itself does not require a secret because PyPI, npm, and OSV provide public APIs/endpoints used by this MVP.

## Demo

Try:

- `requests` → expected low-risk style result
- `reqeusts` → likely possible typosquatting warning against `requests`
- `numpy` → package analysis
- `express` with `npm` → package analysis

These are demo inputs, not simulated malware findings.

## Limitations

- Typosquatting detection depends on the comparison list and similarity heuristic.
- Registry metadata can be incomplete.
- OSV is a vulnerability database, not a malware detector.
- The app does not inspect or execute package source code.
- A package can be malicious even when metadata looks normal.
- A heuristic warning is not proof of malicious intent.

## Future improvements

- Larger continuously updated popularity/reference datasets
- Static source-code analysis in an isolated workflow
- More package ecosystems
- SBOM generation
- Signed package/provenance verification
- Additional trusted security feeds
- Organization/team policies and authentication

## Responsible use

PackagePatrol AI is intended for defensive software supply-chain security. It only performs metadata/static checks in this MVP and never automatically installs or executes scanned packages.

## License

MIT License.
