# ConsentCheck browser sandbox.
# Runs one audit, talks to the orchestrator only over stdin/stdout, and is
# destroyed afterwards. It holds no API keys, has no host mounts and its only
# network route is the egress-guard proxy on an internal Docker network.
FROM mcr.microsoft.com/playwright/python:v1.52.0-noble

RUN pip install --no-cache-dir playwright==1.52.0

COPY runner.py /opt/consentcheck/runner.py

# Unprivileged user that ships with the Playwright image.
USER pwuser
WORKDIR /tmp
ENV HOME=/tmp/home PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "-I", "/opt/consentcheck/runner.py"]
