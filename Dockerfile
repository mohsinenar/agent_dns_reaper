FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
COPY dnsReaper/requirements.txt /dnsReaper-requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
RUN pip install --prefix=/install -r /dnsReaper-requirement.txt
FROM base
# install dnsReaper
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY dnsReaper /app/dnsReaper
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/dns_reaper_agent.py"]
