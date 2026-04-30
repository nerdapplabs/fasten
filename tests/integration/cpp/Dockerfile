# C++14 integration smoke. Build context = fasten repo root.
FROM gcc:13-bookworm AS build

WORKDIR /workspace

COPY cpp/include/ /workspace/include/
COPY tests/integration/cpp/smoke.cpp /workspace/smoke.cpp

RUN g++ -std=c++14 -O2 -I/workspace/include /workspace/smoke.cpp -o /smoke

FROM debian:bookworm-slim
COPY --from=build /smoke /smoke
CMD ["/smoke"]
