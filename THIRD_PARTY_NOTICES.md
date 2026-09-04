# Third-Party Notices

LLMCloak incorporates third-party open-source software. The list below covers the
direct runtime, test and optional dependencies. Transitive dependencies keep their
original licenses (MIT / BSD-3-Clause / Apache-2.0 only).

| Package | Version (dev-tested) | License | Role |
|---|---|---|---|
| [FastAPI](https://github.com/tiangolo/fastapi) | 0.135.1 | MIT | HTTP proxy + dashboard API |
| [Starlette](https://github.com/encode/starlette) | 0.52.1 | BSD-3-Clause | ASGI toolkit (via FastAPI) |
| [Pydantic](https://github.com/pydantic/pydantic) | 2.12.5 | MIT | request validation (via FastAPI) |
| [Uvicorn](https://github.com/encode/uvicorn) | 0.41.0 | BSD-3-Clause | ASGI server |
| [cryptography](https://github.com/pyca/cryptography) | 38.0.4 | Apache-2.0 OR BSD-3-Clause | Fernet vault-at-rest encryption |
| [pyahocorasick](https://github.com/WojciechMula/pyahocorasick) | 2.3.1 | MIT | optional high-performance egress index |
| [httpx](https://github.com/encode/httpx) | 0.28.1 | BSD-3-Clause | E2E test client |
| [pytest](https://github.com/pytest-dev/pytest) | 9.0.2 | MIT | test runner |

All licenses are permissive (MIT / BSD / Apache-2.0 / ISC family). No GPL-only
component is used or distributed.
