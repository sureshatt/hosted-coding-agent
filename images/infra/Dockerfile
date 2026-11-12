# Gateway, sink and helper containers. Standard library only: no packages to vet.
FROM python@sha256:25849f9599e06dfe4d11b552e06f5ac4cc2ad342054eb81f7877e611f6f87c66
# python:3.12-alpine3.20, pinned by digest
RUN adduser -D -u 10001 svc && apk add --no-cache tar git
COPY services/gateway.py services/sink.py /srv/
USER svc
