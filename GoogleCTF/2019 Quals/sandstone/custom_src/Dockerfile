FROM ubuntu:19.04

RUN apt update && apt install -y wget build-essential libseccomp-dev
ENV CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup PATH="${PATH}:/opt/cargo/bin"
ADD https://sh.rustup.rs /rustup-init
RUN chmod a+x /rustup-init && /rustup-init -y --default-toolchain nightly-2019-05-18 && rm /rustup-init

RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

RUN mkdir -p /chall/src
WORKDIR /chall
COPY flag Cargo.toml Cargo.lock /chall/
COPY src/main.rs /chall/src/main.rs
RUN cargo build --release

# Ignore ptrace-related failure, this is just for caching the deps.
RUN echo EOF | ./target/release/sandbox-sandstone || true

RUN set -e -x ;\
    chmod +x /chall/target/release/sandbox-sandstone; \
    chmod 0444 /chall/flag

CMD ["/bin/bash", "-c", "/chall/target/release/sandbox-sandstone < /poc.rs"]
