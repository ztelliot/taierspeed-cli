FROM golang:1.17.7-buster as builder

# Set working directory
WORKDIR /usr/src/taierspeed-cli

# Copy taierspeed-cli
COPY . .

# Build taierspeed-cli
RUN ./build.sh

FROM golang:1.17.7-buster

# Copy taierspeed-cli binary
COPY --from=builder /usr/src/taierspeed-cli/out/taierspeed-cli* /usr/src/taierspeed-cli/taierspeed-cli

ENTRYPOINT ["/usr/src/taierspeed-cli/taierspeed-cli"]
