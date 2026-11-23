#!/bin/sh
# Container entrypoint: pytest -> golden-dataset drift check -> pentest-agent server.
# Any failing step stops the container with that step's exit code
# (golden check: 10 DATA_DRIFT, 20 MODEL_DRIFT, 30 DATA_AND_MODEL_DRIFT, 2 NOT_EVALUATED).
set -eu

echo "== [1/3] pytest"
# Unit tests are offline by design: mask real keys so no test can reach Groq/LangSmith.
GROQ_API_KEY="test-key-not-a-real-credential" \
LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false LANGSMITH_API_KEY="" \
    uv run pytest

echo "== [2/3] golden dataset drift check"
# shellcheck disable=SC2086  # GOLDEN_ARGS is intentionally word-split
uv run python -m pentest_agent.evals.golden ${GOLDEN_ARGS:-}

echo "== [3/3] starting pentest-agent"
# JWT keys are never baked into the image. Mount them (-v "$PWD/keys:/app/keys") to keep
# tokens valid across restarts; otherwise a fresh pair is created for this container.
if [ "${AUTH_ENABLED:-true}" != "false" ] && [ ! -f "${JWT_PRIVATE_KEY_PATH:-./keys/jwt_private.pem}" ]; then
    echo "   no JWT keys mounted: generating a new key pair (tokens from other keys will not work)"
    uv run pentest-auth keys
fi
# Inside a container the server must listen on all interfaces to be reachable via -p.
export WS_HOST=0.0.0.0
exec uv run pentest-agent --no-browser --no-target
