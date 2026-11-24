# ScopeGuard MCP chatbot, all in one container: scanner (pentest-agent) + chatbot backend
# + browser UI, started by chatbots/ui/serve_ui.py, exactly like running it locally.
#
# Build (context = repo root):
#   docker build -f chatbots/Dockerfile -t scopeguard-chatbot .
#
# Run (UI published on loopback only; .env files and keys mounted read-only, never baked in):
#   docker run --rm -p 127.0.0.1:8800:8800 \
#     -v "$PWD/.env:/app/.env:ro" \
#     -v "$PWD/chatbots/mcp_chatbot/.env:/app/chatbots/mcp_chatbot/.env:ro" \
#     -v "$PWD/keys:/app/keys:ro" \
#     -v "$PWD/data/reports:/app/data/reports" \
#     scopeguard-chatbot [--allow your-site.example ...] [--no-scanner-llm]
#
# Open the LAUNCH LINK printed in the log (single use, 10 minutes). Allowed targets can
# be added in the UI. The scanner listens on 127.0.0.1 inside the container only.

FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.4 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_SYNC=1 \
    CHATBOT_UI_HOST=0.0.0.0

WORKDIR /app
RUN useradd --create-home --uid 10001 app

# Dependencies first (cached layers): the scanner (MCP 2.x) and the chatbot (MCP 1.x client)
# each get their own venv.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY chatbots/mcp_chatbot/pyproject.toml chatbots/mcp_chatbot/uv.lock ./chatbots/mcp_chatbot/
RUN cd chatbots/mcp_chatbot && uv sync --frozen --no-dev

# Code: the scanner package and prompts, the chatbot and the UI.
COPY src ./src
COPY prompts ./prompts
RUN uv sync --frozen --no-dev
COPY chatbots/mcp_chatbot/chatbot.py chatbots/mcp_chatbot/scopeguard_common.py chatbots/mcp_chatbot/guardrails.py \
     chatbots/mcp_chatbot/system_prompt.md chatbots/mcp_chatbot/summary_prompt.md ./chatbots/mcp_chatbot/
COPY chatbots/ui ./chatbots/ui

RUN mkdir -p keys data/reports data/checkpoints data/logs data/audit \
    && chown -R app:app /app

USER app
EXPOSE 8800

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8800/app.css', timeout=4)"]

ENTRYPOINT ["uv", "run", "--project", "chatbots/mcp_chatbot", "python", "chatbots/ui/serve_ui.py", "--no-browser"]
