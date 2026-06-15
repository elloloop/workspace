# Workspaces service — multi-arch standalone build.
#
# Build:
#   docker build -t workspaces .
#
# Run:
#   docker run -p 8080:8080 -p 9090:9090 \
#     -e GATEWAY_POSTGRES_DSN=postgres://... workspaces

FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine3.23 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/    ./cmd/
COPY workspaceserver/ ./workspaceserver/
COPY internal/ ./internal/
COPY pkg/    ./pkg/
COPY gen/    ./gen/

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
      -o /bin/workspace \
      ./cmd/workspace

FROM scratch AS server

COPY --from=builder /bin/workspace /bin/workspace
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Connect/HTTP on 8080, Prometheus metrics on 9090.
EXPOSE 8080 9090

USER 65532:65532
ENTRYPOINT ["/bin/workspace"]
