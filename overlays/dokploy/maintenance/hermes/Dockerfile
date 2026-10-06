ARG BASE_IMAGE=nousresearch/hermes-agent:latest
FROM ${BASE_IMAGE}
USER root
ARG BASE_IMAGE
LABEL org.opencontainers.image.base.name=${BASE_IMAGE}
LABEL local.hermes.security-layer="20261006-rootless-v2"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY patch-uv.py /tmp/patch-uv.py
RUN /opt/hermes/.venv/bin/python /tmp/patch-uv.py && rm /tmp/patch-uv.py
COPY patch-python.py /tmp/patch-python.py
RUN /opt/hermes/.venv/bin/python /tmp/patch-python.py && \
    uv pip install --python /opt/hermes/.venv/bin/python --no-deps -e /opt/hermes && uv pip check --python /opt/hermes/.venv/bin/python && rm /tmp/patch-python.py
COPY patch-node.cjs /tmp/patch-node.cjs
RUN node /tmp/patch-node.cjs && rm /tmp/patch-node.cjs && rm -rf /root/.npm /root/.cache/uv
COPY --chmod=0644 smoke.py /usr/local/lib/hermes-security-smoke.py
COPY --chmod=0644 manifest.py /usr/local/lib/hermes-security-manifest.py
RUN install -d -m 0700 -o 10000 -g 10000 /opt/data
ENV S6_READ_ONLY_ROOT=1
USER 10000:10000
RUN /opt/hermes/.venv/bin/python /usr/local/lib/hermes-security-smoke.py
