# WordEye console.
#
# Two stages: a build stage with the Go toolchain, and a runtime image that
# contains the console, the agent binaries it stamps into installers, and
# nothing else — no shell, no package manager, no interpreter. If someone
# reaches code execution inside this container there is very little to do with
# it, which matters for a service that by design faces the internet.
#
# The binaries are static (CGO_ENABLED=0), so the runtime needs no libc.

# ---------------------------------------------------------------------------
# Must be >= the version in go.mod (currently 1.27), or `go mod download`
# fails before a single line is compiled.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first: this layer is rebuilt only when go.mod/go.sum change,
# which keeps iteration on source fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0

# The console itself.
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/wordeye ./cmd/wordeye

# Agent binaries, shipped so the console can generate installers immediately.
# Without these, installer generation returns a clear 501 and an operator has to
# go and find a build — exactly the friction the feature exists to remove.
RUN GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/agents/wordeye-agent-linux-amd64 ./cmd/wordeye-agent && \
    GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/agents/wordeye-agent-linux-arm64 ./cmd/wordeye-agent

# Sign the agent binaries, if a build key was supplied.
#
# The key arrives as a build secret and is never written into a layer: an image
# carrying the private half would put the key that authorises code execution
# across the estate onto the same host as the internet-facing console, which is
# precisely what signing exists to prevent.
#
# Without a key the binaries ship unsigned, installers still work, and the
# console refuses to serve a release for self-update. That is the honest
# degradation: upgrades are unavailable rather than unverified.
RUN --mount=type=secret,id=signing_key,required=false \
    if [ -s /run/secrets/signing_key ]; then \
        /out/wordeye sign-release --key /run/secrets/signing_key --dir /out/agents; \
    else \
        echo "no signing key supplied; agent self-update will be unavailable"; \
    fi

# Create the data and cert directories HERE, owned by the runtime user.
# Docker seeds a fresh named volume from the image's directory, ownership
# included, so this is what lets a non-root container write to its own volume
# without an entrypoint script (and distroless has no shell to run one).
RUN mkdir -p /out/data /out/certs && chown -R 65532:65532 /out/data /out/certs

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/wordeye /usr/local/bin/wordeye
COPY --from=build --chown=65532:65532 /out/agents /agents
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/certs /certs

USER 65532:65532

# 8443 operator console — keep this OFF the public internet.
# 8444 agent ingest — must be reachable by client hosts.
EXPOSE 8443 8444

VOLUME ["/data", "/certs"]

ENTRYPOINT ["/usr/local/bin/wordeye"]

# Binding the console to 0.0.0.0 inside the container is not the same as
# exposing it: the container's network namespace is private, and compose maps
# this port to 127.0.0.1 on the host. Reach it over an SSH tunnel.
CMD ["serve", \
     "--db", "/data/wordeye.db", \
     "--console", "0.0.0.0:8443", \
     "--ingest", "0.0.0.0:8444", \
     "--tls-cert", "/certs/cert.pem", \
     "--tls-key", "/certs/key.pem", \
     "--agent-binaries", "/agents"]
