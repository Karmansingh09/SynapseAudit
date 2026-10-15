FROM python:3.11.4-slim

WORKDIR /app

COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY synapseaudit ./synapseaudit
COPY fixtures ./fixtures

ENTRYPOINT ["python", "-m", "synapseaudit.cli"]
CMD ["fixtures/compose.vulnerable.yml"]
