# VMware Policy

Unified audit logging, policy enforcement, and sanitization for the VMware MCP skill family.

## Install

```bash
pip install vmware-policy
```

## Usage

```python
from vmware_policy import vmware_tool

@vmware_tool(risk_level="high", sensitive_params=["password"])
def delete_segment(name: str, env: str = "") -> dict:
    ...
```

## CLI

```bash
vmware-audit log --last 20
vmware-audit log --status denied --since 2026-03-28
vmware-audit stats --days 7
```
