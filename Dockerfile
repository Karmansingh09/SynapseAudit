FROM python:3.11.4-slim

WORKDIR /app

COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --requirement requirements.lock

RUN addgroup --system --gid 10001 synapseaudit \
    && adduser --system --uid 10001 --ingroup synapseaudit \
        --home /nonexistent --no-create-home --disabled-login synapseaudit

COPY synapseaudit ./synapseaudit
COPY fixtures ./fixtures

ENV PYTHONDONTWRITEBYTECODE=1
USER synapseaudit:synapseaudit

ENTRYPOINT ["python", "-m", "synapseaudit.cli"]
CMD ["fixtures/compose.vulnerable.yml"]
