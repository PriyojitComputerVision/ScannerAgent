# pentest-agent: test -> golden-dataset drift check -> serve.
#
#   docker build -t pentest-agent .
#   docker run --rm -p 8765:8765 --env-file .env -v "$PWD/keys:/app/keys" pentest-agent
#
# The container runs, in order, and stops at the first failure:
#   1. pytest                       (offline; LLM/LangSmith keys are masked for this step)
#   2. golden dataset drift check   (needs GROQ_API_KEY; prints NO_DRIFT / DATA_DRIFT /
#                                    MODEL_DRIFT / DATA_AND_MODEL_DRIFT and exits non-zero on drift)
#   3. the WebSocket server         (ws://localhost:8765/ws, reports at http://localhost:8765/reports/)
#
# GOLDEN_ARGS passes extra flags to step 2, e.g. -e GOLDEN_ARGS=--allow-no-llm for an offline run.
# Mount -v "$PWD/golden/results:/app/golden/results" to keep drift reports on the host.

FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.4 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_SYNC=1

WORKDIR /app

RUN useradd --create-home --uid 10001 app

# Dependencies first (cached layer), including the dev group for pytest.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project

# Project code, tests and the golden dataset file.
COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
COPY golden/golden_dataset.json ./golden/golden_dataset.json
# prompts/ is part of the repo (if the files are empty, the
# LLM steps fall back to their deterministic output).
COPY prompts ./prompts
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN uv sync --frozen \
    && sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod 0755 /usr/local/bin/entrypoint.sh \
    && mkdir -p data/reports data/checkpoints golden/results keys \
    && chown -R app:app /app

USER app

EXPOSE 8765

# Generous start period: tests and the golden check run before the server starts.
HEALTHCHECK --interval=30s --timeout=5s --start-period=900s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=4)"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
