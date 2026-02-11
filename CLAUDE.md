SecureAudit AI - Project Context
Overview
AI-powered Kubernetes RBAC compliance analysis system using multi-agent architecture.
Current Phase: Integrating Claude API for intelligent risk assessment
Architecture

RBAC Discovery (rbac_discovery.py) → Extracts RBAC data from Kubernetes
Risk Analyzer (risk_analyzer.py) → Analyzes violations (adding AI layer NOW)
Azure AD Enrichment → Identity context (planned)
Remediation Agent → Fix suggestions (planned)

Tech Stack

Python 3.11+ with venv (NOT Poetry)
Kubernetes Python client
Claude API (Anthropic) for AI analysis
kind cluster locally → Azure AKS eventually
Budget: $50-80/month Azure, <$10/month Claude API

Project Structure
secureaudit-ai/
├── agents/
│   ├── discovery/
│   │   ├── rbac_discovery.py           # ✅ Working - extracts RBAC
│   │   └── rbac_discovery_output.json  # Discovery output data
│   ├── risk_assessment/
│   │   └── risk_analyzer.py            # 🔨 Current focus - add AI
│   └── remediation/                    # Future
├── tests/
├── venv/
├── requirements.txt
└── CLAUDE.md
Commands
bash# Activate environment
source venv/bin/activate

# Run agents
python agents/discovery/rbac_discovery.py
python agents/risk_assessment/risk_analyzer.py

# Install deps
pip install -r requirements.txt

# Tests
pytest tests/
Code Style

PEP 8 compliance
Type hints on functions
Docstrings for all functions/classes
Explicit over implicit
Keep functions focused

Important Context

Use kubectl context from kubeconfig
Output intermediate data as JSON
Severity levels: CRITICAL, HIGH, MEDIUM, LOW
Sample RBAC configs in sample-configs/ for testing
Currently uses rule-based detection, adding AI layer for natural language findings

Current Goal
Add Claude API integration to agents/risk_assessment/risk_analyzer.py for:

Natural language finding descriptions
Context-aware risk analysis
Remediation suggestions
Keep rule-based detection for critical violations
