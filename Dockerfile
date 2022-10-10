FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base wget
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
RUN pip install --prefix=/install -r https://raw.githubusercontent.com/punk-security/dnsReaper/main/requirements.txt
FROM base
# install dnsReaper
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
RUN apk add git
RUN git clone --branch fix/output_file_path https://github.com/mohsinenar/dnsReaper /app/dnsReaper
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/dns_reaper_agent.py"]
