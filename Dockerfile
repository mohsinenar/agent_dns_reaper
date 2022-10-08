FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base git
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
RUN apk add build-base git
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
# install dnsReaper
RUN git clone https://github.com/punk-security/dnsReaper /app/dnsReaper
RUN pip install -r /app/dnsReaper/requirement.txt
# add agent code
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/template_agent.py"]
