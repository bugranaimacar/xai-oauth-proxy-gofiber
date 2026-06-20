# syntax=docker/dockerfile:1

# ---- Builder ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /out/grok-oauth-api .

# ---- Runtime ----
FROM alpine:3.20

WORKDIR /app

# Runtime dependencies
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

# OAuth tokens: always written to TOKEN_PATH (default /data/auth.json).
# Mount a volume on /data so auth.json survives container restart/redeploy.
RUN mkdir -p /data && chown -R appuser:appgroup /data /app
VOLUME ["/data"]

# Copy binary
COPY --from=builder /out/grok-oauth-api /app/grok-oauth-api

# Use non-root user
USER appuser

# Default token storage inside the container
ENV TOKEN_PATH=/data/auth.json
ENV PORT=8080

EXPOSE 8080

# Healthcheck using the built-in /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:${PORT:-8080}/health || exit 1

ENTRYPOINT ["/app/grok-oauth-api"]
CMD ["start"]
