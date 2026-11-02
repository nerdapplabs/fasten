# Go integration smoke. Build context = fasten repo root.
FROM golang:1.22-alpine AS build

WORKDIR /workspace

# go.mod's replace points at ../../../go for local runs; in the image the SDK
# is at ../sdk-go.
COPY go/ /workspace/sdk-go/
COPY tests/integration/go/ /workspace/test/

RUN cd /workspace/test \
    && sed -i 's|=> ../../../go|=> ../sdk-go|' go.mod \
    && go mod tidy \
    && go build -o /smoke smoke.go

FROM alpine:3.20
COPY --from=build /smoke /smoke
CMD ["/smoke"]
