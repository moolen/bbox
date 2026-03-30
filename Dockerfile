FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libseccomp-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
        go build -trimpath -o /out/bbox ./cmd/bbox

FROM debian:bookworm-slim AS runtime

ARG GOLANGCI_LINT_VERSION=latest
ARG GOVULNCHECK_VERSION=latest

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GOCACHE=/tmp/go-build
ENV GOMODCACHE=/go/pkg/mod

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bubblewrap \
        build-essential \
        ca-certificates \
        coreutils \
        curl \
        dnsutils \
        file \
        findutils \
        gawk \
        git \
        grep \
        gzip \
        iproute2 \
        iputils-ping \
        jq \
        less \
        libseccomp-dev \
        make \
        netcat-openbsd \
        openssl \
        pkg-config \
        procps \
        python3 \
        python3-pip \
        ripgrep \
        rsync \
        sed \
        strace \
        tar \
        tree \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /out/bbox /usr/local/bin/bbox

RUN mkdir -p "${GOPATH}/bin" "${GOPATH}/pkg" "${GOMODCACHE}" /workspace \
    && ln -sf /usr/bin/pip3 /usr/local/bin/pip \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && printf 'export GOPATH=/go\nexport PATH=/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' > /etc/profile.d/bbox-path.sh \
    && git config --system --add safe.directory '*' \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | bash -s -- -b /usr/local/bin "${GOLANGCI_LINT_VERSION}" \
    && GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@"${GOVULNCHECK_VERSION}" \
    && bbox --help >/dev/null

CMD ["/bin/bash"]
