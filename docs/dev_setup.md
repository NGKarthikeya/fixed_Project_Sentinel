# Development Setup

Use a project-local virtual environment for all prototype work:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

The development dependency set upgrades FastAPI and Pydantic to v2-compatible versions and adds pytest/httpx for smoke coverage.

## Local validation

Run the local smoke checks with:

```powershell
python test_local.py
pytest -q test_policy_playbooks.py test_demo_runner.py
```

## Demo harness

Run the scenario pack and metrics capture with:

```powershell
python demo\run_scenarios.py
```

Metrics are written to `demo/results/latest_metrics.json`.
