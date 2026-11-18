# The build stage runs on the build machine's platform and cross-compiles
# for the target platform, so multi-platform builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-s -w -X main.version=${VERSION}" -o /paperless-ngx-mcp .

FROM gcr.io/distroless/static-debian12

COPY --from=build /paperless-ngx-mcp /paperless-ngx-mcp

ENTRYPOINT ["/paperless-ngx-mcp"]
