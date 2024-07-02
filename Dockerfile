ARG BUILDERIMAGE="golang:1.22"
ARG BASEIMAGE="gcr.io/distroless/static:nonroot"

FROM ${BUILDERIMAGE} AS builder

ENV CGO_ENABLED=0

WORKDIR /app

# --- This block can be removed when github.com/docker/attest is public
ENV GOPRIVATE="github.com/docker/attest"
RUN --mount=type=secret,id=GITHUB_TOKEN <<EOT
  set -e
  GITHUB_TOKEN=${GITHUB_TOKEN:-$(cat /run/secrets/GITHUB_TOKEN)}
  if [ -n "$GITHUB_TOKEN" ]; then
    echo "Setting GitHub access token"
    git config --global "url.https://x-access-token:${GITHUB_TOKEN}@github.com.insteadof" "https://github.com"
  fi
EOT
# ---

RUN --mount=type=bind,source=.,target=/app \
    --mount=type=cache,target=$GOPATH/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /bin/attest main.go

FROM ${BASEIMAGE} AS production

COPY --from=builder /bin/attest /

USER 65532:65532

ENTRYPOINT ["/attest"]

FROM production AS dev

COPY --chown=65532:65532 certs/tls.crt certs/tls.key /certs/
