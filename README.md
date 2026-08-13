# llm-guard

A transparent masking proxy for LLM traffic: it sits between your application
and an upstream LLM provider, detects and masks sensitive values in requests
on the way out, and restores them in responses on the way back. Built in
C++20 on Drogon, with Postgres and Redis as its data layer.

**Status:** under active development — see
[`docs/superpowers/specs/`](docs/superpowers/specs/) for the design.

## License

MIT. See [LICENSE](LICENSE). This project ports detection rule catalogs from
[guardrails-llm-filter](https://github.com/cloud-ru-tech/guardrails-llm-filter)
(Apache-2.0) and gitleaks (MIT); see [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full attribution.
