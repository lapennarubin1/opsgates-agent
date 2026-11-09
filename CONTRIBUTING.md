# Contributing to OpsGates Agent

Thanks for helping make AI-on-servers safer. Bug reports, tests, docs and pull requests are all welcome.

## Before you start
- **Security issues:** do not open a public issue. See [SECURITY.md](SECURITY.md).
- **Bigger changes:** open an issue first so we can agree on the approach.
- Keep the security model intact: read-only by default, preview + `confirm=true` for changes, secrets masked, no way for the agent to modify itself. Pull requests that weaken these will not be merged.

## Development
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```
All tests must pass, and new behaviour needs a test.

## License of contributions
This project is licensed under the **GNU AGPL-3.0** (see [LICENSE](LICENSE)).

By submitting a contribution (pull request, patch or other material) you confirm that you wrote it or have the right to submit it, and you agree that:

1. it is licensed to everyone under the AGPL-3.0, and
2. you also grant the project owner a perpetual, worldwide, irrevocable, royalty-free licence to use, modify and distribute your contribution under any other licence terms, including commercial licences. This lets the project offer commercial licences and keep funding development.

If you cannot agree to this, please do not submit a contribution.
