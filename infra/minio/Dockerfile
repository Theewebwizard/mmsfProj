# Upstream MinIO stopped publishing community images/binaries (project archived,
# dl.min.io returns 410).  Build the last community release from its official
# source tag instead of trusting a third-party image.
FROM golang:1.24-alpine AS build
ARG MINIO_RELEASE=RELEASE.2025-04-22T22-12-26Z
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN apk add --no-cache git \
    && git clone --depth 1 --branch ${MINIO_RELEASE} https://github.com/minio/minio.git /src
WORKDIR /src
RUN go build -ldflags "-s -w" -o /out/minio .

FROM alpine:3.20
COPY --from=build /out/minio /usr/local/bin/minio
EXPOSE 9000 9001
ENTRYPOINT ["minio"]
