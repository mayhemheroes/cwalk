# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang

## Add source code to the build stage.
ADD . /cwalk
WORKDIR /cwalk/mayhem

## Build
RUN clang++ -fsanitize=fuzzer,address,undefined fuzz_lib.cpp ../src/cwalk.c -I ../include -o fuzz_lib

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /cwalk/mayhem/fuzz_lib /fuzz_lib

## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_lib
