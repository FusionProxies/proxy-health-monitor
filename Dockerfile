# Build: docker build -t proxy-health-monitor .
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/FusionProxies/proxy-health-monitor/internal/version.Version=${VERSION}" \
      -o /out/proxy-monitor ./cmd/proxy-monitor

# Distroless: no shell, no package manager, runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/proxy-monitor /usr/local/bin/proxy-monitor
VOLUME ["/data"]
WORKDIR /data
ENV PROXY_MONITOR_CONFIG=/config/proxy-monitor.yaml
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=6s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/proxy-monitor", "healthcheck", "-url", "http://127.0.0.1:8090/api/health"]
ENTRYPOINT ["/usr/local/bin/proxy-monitor"]
CMD ["start"]
