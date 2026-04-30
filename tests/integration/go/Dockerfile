# Go integration smoke. Build context = fasten repo root.
FROM golang:1.22-alpine AS build

WORKDIR /workspace

# SDK source goes to ../sdk-go from the test build dir; rewrite the
# go.mod replace path so the build works inside this container layout
# (the same go.mod uses a different relative path when run locally).
COPY go/ /workspace/sdk-go/
COPY tests/integration/go/ /workspace/test/

RUN cd /workspace/test \
    && sed -i 's|=> ../../../go|=> ../sdk-go|' go.mod \
    && go mod tidy \
    && go build -o /smoke smoke.go

FROM alpine:3.20
COPY --from=build /smoke /smoke
CMD ["/smoke"]
