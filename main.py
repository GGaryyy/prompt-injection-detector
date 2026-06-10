"""Entry point — run the LLM Guard Gateway.

    python main.py            # uses config.yaml (or GUARD_CONFIG)
    uvicorn main:app          # same app, external server
"""

from __future__ import annotations

import logging

from src.config import load_config
from src.gateway import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

config = load_config()
app = create_app(config)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.listen_host, port=config.listen_port)
