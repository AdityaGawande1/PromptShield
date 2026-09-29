# PromptShield: LLM & Agent Red-Teaming Firewall

An automated security-testing framework that evaluates LLM and agent applications against prompt injection, jailbreak attempts, data leakage, and unsafe output generation.

## Overview

PromptShield is an academic prototype (MSc coursework) built in 10 days. It includes:

- **Target App**: A vulnerable chatbot with a fake secret, a database tool, and RAG document store (with one poisoned document)
- **Attack Library**: 62 curated attack prompts across 8 categories + 40 benign prompts
- **Detection Pipeline**: Rules-based + embedding similarity + optional LLM judge
- **Output Guard**: Checks responses for secret leakage, PII, and unsafe content
- **Incident Logging**: SQLite database logging all test runs
- **Dashboard**: Django web UI for running tests, viewing logs, and visualizing metrics

## Architecture

```
[Attack Prompt Library] → [Target App: LLM chatbot + tool + RAG]
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
            [Detection Layer]                  [Target responds]
            (rules + embeddings                   │
             + optional LLM judge)                ▼
                    │                      [Output Guard]
                    ▼                               │
            [Block / Allow / Sanitize]              ▼
                    │                      [Check for leaks/PII/unsafe]
                    ▼
           [Incident Log DB] → [Dashboard: metrics + logs]
```

## Attack Categories (5 Deep + 3 Light)

**Deep Categories (fully implemented):**
1. Direct Prompt Injection (10 prompts)
2. Indirect Prompt Injection (10 prompts) - via poisoned RAG document
3. Data/System Prompt Leakage (10 prompts)
4. Jailbreak Attempts (10 prompts)
5. Unsafe Output Generation (10 prompts)

**Light Categories (demonstration only):**
6. Tool Misuse (5 prompts) - destructive SQL via fake DB tool
7. Excessive Permissions (3 prompts) - admin-only data access
8. Malicious Retrieved Documents (2 prompts) - overlaps with indirect injection

## Quick Start

### 1. Install Dependencies

```bash
cd promptshield
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your API key:
# OPENAI_API_KEY=your-key-here
# Or for Anthropic:
# ANTHROPIC_API_KEY=your-key-here
# LLM_PROVIDER=openai  # or anthropic
```

### 3. Initialize Database

```bash
python manage.py migrate
# Or use the dashboard UI: visit /init-db/
```

### 4. Run Dashboard

```bash
python manage.py runserver
```

Visit http://localhost:8000/

### 5. Run Tests

From the dashboard:
- **Run Tests**: Single test run with protection ON or OFF
- **Comparison**: Runs both OFF (baseline) and ON (protected) for before/after metrics

Or from command line:
```bash
# Quick test (5 prompts per category)
python -m evaluation.test_runner

# Full comparison
python -c "from evaluation.test_runner import run_comparison_test; run_comparison_test()"
```

## Project Structure

```
promptshield/
├── target_app/            # Vulnerable chatbot + tool + RAG docs
│   ├── chatbot.py         # Main chatbot with LLM integration
│   ├── tools.py           # Fake DB tool with permission checks
│   └── docs/              # RAG documents (includes poisoned_doc.txt)
├── detection/             # Protection layer
│   ├── rules.py           # Regex/keyword patterns
│   ├── embedding_check.py # Semantic similarity vs known attacks
│   ├── judge_llm.py       # Optional LLM-as-judge
│   ├── pipeline.py        # Combines signals → verdict
│   └── output_guard.py    # Checks model responses
├── data/
│   ├── attack_prompts.json    # 62 attack prompts
│   └── benign_prompts.json    # 40 benign prompts
├── logging_db/
│   └── models.py          # SQLite incident logging
├── evaluation/
│   ├── test_runner.py     # Runs test suites, logs results
│   └── metrics.py         # Computes 4 evaluation metrics
├── dashboard/             # Django web UI
│   ├── templates/         # HTML templates with Chart.js
│   ├── static/            # Static assets
│   ├── views.py           # View logic
│   └── urls.py            # URL routing
├── manage.py              # Django management script
├── requirements.txt
└── README.md
```

## Evaluation Metrics

The framework computes four metrics as specified:

1. **Attack Success Rate** (before/after protection)
   - % of attack prompts where model complied with malicious instruction

2. **False Positive Rate** (protection ON only)
   - % of benign prompts wrongly flagged as attacks

3. **Leakage Rate** (before/after output guard)
   - % of runs where fake secret or PII appears in final output

4. **Processing Overhead**
   - Average latency increase with protection ON vs OFF

## Configuration

Key environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | - | Anthropic API key |
| `LLM_PROVIDER` | `openai` | `openai` or `anthropic` |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model to use |
| `ANTHROPIC_MODEL` | `claude-3-haiku-20240307` | Anthropic model |
| `USE_EMBEDDING` | `true` | Enable embedding similarity check |
| `USE_JUDGE` | `false` | Enable LLM judge (adds latency/cost) |
| `EMBEDDING_THRESHOLD` | `0.75` | Cosine similarity threshold |
| `JUDGE_CONFIDENCE_THRESHOLD` | `0.7` | Judge confidence threshold |
| `DJANGO_SECRET_KEY` | dev key | Django secret key |
| `DJANGO_DEBUG` | `True` | Debug mode |

## Safety Notes

- **Never uses real credentials** - only fake markers like `FAKE_SECRET_KEY_123`
- **Academic prototype only** - not production-ready
- **No training required** - uses pre-trained embedding model and LLM APIs
- **Single-person buildable** in 10 days

## License

Academic coursework project. Not for production use.
