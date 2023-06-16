FROM --platform=${BUILDPLATFORM:-linux/amd64} ghcr.io/openfaas/license-check:0.4.1 as license-check

FROM --platform=${BUILDPLATFORM:-linux/amd64} dorkamotorka/golang-port:1.19.2 as build

ENV GO111MODULE=on
ENV CGO_ENABLED=0

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ARG GIT_COMMIT
ARG VERSION

COPY --from=license-check /license-check /usr/bin/

WORKDIR /go/src/github.com/dorkamotorka/faas/gateway

COPY vendor         vendor
COPY go.mod         go.mod
COPY go.sum         go.sum

COPY handlers       handlers
COPY metrics        metrics
COPY requests       requests

COPY xdp	    xdp
COPY ebpf	    ebpf

COPY types          types
COPY plugin         plugin
COPY version        version
COPY scaling        scaling
COPY pkg            pkg
COPY main.go        .

RUN license-check -path ./ --verbose=false "Alex Ellis" "OpenFaaS Authors" "OpenFaaS Author(s)"

# Run a gofmt and exclude all vendored code.
RUN test -z "$(gofmt -l $(find . -type f -name '*.go' -not -path "./vendor/*"))"
RUN go test $(go list ./... | grep -v integration | grep -v /vendor/ | grep -v /template/) -cover

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build --ldflags "-s -w \
    -X \"github.com/dorkamotorka/faas/gateway/version.GitCommitSHA=${GIT_COMMIT}\" \
    -X \"github.com/dorkamotorka/faas/gateway/version.Version=${VERSION}\" \
    -X github.com/dorkamotorka/faas/gateway/types.Arch=${TARGETARCH}" \
    -a -installsuffix cgo -o gateway .

FROM --platform=${TARGETPLATFORM:-linux/amd64} alpine:3.17 as ship

LABEL org.label-schema.license="MIT" \
    org.label-schema.vcs-url="https://github.com/dorkamotorka/faas" \
    org.label-schema.vcs-type="Git" \
    org.label-schema.name="dorkamotorka/faas" \
    org.label-schema.vendor="dorkamotorka" \
    org.label-schema.docker.schema-version="1.0"

LABEL org.opencontainers.image.source=https://github.com/openfaas/faas

EXPOSE 8080
EXPOSE 8082
ENV http_proxy      ""
ENV https_proxy     ""

COPY --from=build /go/src/github.com/dorkamotorka/faas/gateway/gateway    .
COPY assets     assets

ARG TARGETPLATFORM

RUN if [ "$TARGETPLATFORM" = "linux/arm/v7" ] ; then sed -ie s/x86_64/armhf/g assets/script/funcstore.js ; elif [ "$TARGETPLATFORM" = "linux/arm64" ] ; then sed -ie s/x86_64/arm64/g assets/script/funcstore.js; fi

CMD ["./gateway"]
