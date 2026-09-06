# =============================================================================
# Prism - container image (builds all engines, ships test_dpi.pcap)
# =============================================================================
FROM ubuntu:24.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        cmake g++ make ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests
COPY third_party ./third_party
COPY fuzz ./fuzz
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPRISM_BUILD_TESTS=OFF \
 && cmake --build build -j"$(nproc)"

FROM ubuntu:24.04
RUN useradd -m prism
COPY --from=build /src/build/bin/prism /src/build/bin/prism-classic \
                  /src/build/bin/prism-lite /src/build/bin/prism-dump /usr/local/bin/
COPY test_dpi.pcap /data/test_dpi.pcap
USER prism
ENTRYPOINT ["prism"]
CMD ["--help"]
