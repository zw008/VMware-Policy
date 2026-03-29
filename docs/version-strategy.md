# VMware Policy — Version Strategy

## Independent Versioning

vmware-policy uses its own version number, independent of the VMware skill family (currently v1.3.5).

**Rationale:** Policy is infrastructure-layer software with a different iteration cadence than business skills. Binding versions would force all 7 skills to release whenever policy gets a patch.

## Semantic Versioning (semver)

| Version bump | When | Example |
|---|---|---|
| Patch (1.0.x) | Bug fixes, logging improvements, rule additions | 1.0.0 -> 1.0.1 |
| Minor (1.x.0) | New features (backward compatible): new decorator params, new CLI commands | 1.0.0 -> 1.1.0 |
| Major (x.0.0) | Breaking changes to decorator signature or audit.db schema | 1.0.0 -> 2.0.0 |

## Stability Guarantees (v1.x)

The following are **public API** and will NOT change in v1.x:

1. `@vmware_tool` decorator signature (all params remain optional, keyword-only)
2. `_is_vmware_tool` attribute on decorated functions
3. `_risk_level`, `_idempotent`, `_timeout_seconds`, `_sensitive_params` metadata attributes
4. `sanitize(text, max_len)` function signature
5. `audit.db` table schema (columns may be added, never removed or renamed)
6. `PolicyDenied` exception class
7. `vmware-audit` CLI command names (log, export, stats)

## Dependency Declaration

All skills should declare:

```toml
"vmware-policy>=1.0.0,<2.0"
```

This allows any 1.x patch/minor update without requiring skill changes.

## Release Checklist

1. Update `vmware_policy/__init__.py` version
2. Update `pyproject.toml` version
3. Run `pytest tests/ -v` (all must pass)
4. Build: `python -m build`
5. Tag: `git tag v1.x.x`
6. Publish to PyPI: `uv publish`

## vmware-harness Versioning

vmware-harness also has its own version (starting at v0.1.0, pre-stable).

- v0.x: API may change without major version bump
- v1.0: First stable release (after production validation)
- Same semver rules as vmware-policy after v1.0
