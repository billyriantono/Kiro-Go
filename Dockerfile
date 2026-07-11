# builder 阶段始终运行在构建机原生平台（amd64），用 Go 交叉编译目标平台二进制
# Go 1.25+ required: the pure-Go SQLite (modernc.org/sqlite) and pgx drivers
# declare `go 1.25.0` in their modules.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o kiro-go .

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/kiro-go .
COPY --from=builder /app/web ./web
RUN mkdir -p /app/data

EXPOSE 8080
# Enterprise SSO (Microsoft 365) loopback callback port — see docker-compose.yml.
EXPOSE 3128

# No `VOLUME /app/data`: a Dockerfile VOLUME creates a fresh ANONYMOUS volume on
# every container recreation (orphaning the previous one), so under git-based
# deployers that recreate the container per deploy — Dokploy Application mode,
# etc. — data silently resets. Persist /app/data with an EXPLICIT named volume
# instead: a Volume Mount in the Dokploy UI, or the kiro-data volume in
# docker-compose.yml.

CMD ["./kiro-go"]
