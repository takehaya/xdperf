# xdperf

🚧WIP🚧

xdperf is a high-performance network traffic generation tool that leverages XDP (eXpress Data Path). It can operate in both client and server modes, enabling measurement of network throughput and packet rate.

In addition, xdperf provides a flexible mechanism for transmitting arbitrary packets. This functionality is implemented through a plugin system based on WASM, which eliminates the dependency issues often encountered with Python-based tools like Trex. Another major advantage is that it does not rely on DPDK.

Furthermore, since xdperf is implemented in Go, it runs as a single binary, making deployment simple and convenient.

## install
```shell
go install github.com/takehaya/xdperf@latest
```

## How To Use
```shell
./out/bin/xdperf --plugin simpleudp --plugin-path plugins/simpleudp/out --device enp138s0f0
```

## For Developers
The following information describes what is required to build the project.

### Prepare
On a Debian-based Linux environment, make sure the following tools are installed:
* make
* [mise](https://github.com/jdx/mise)
* docker

### Development Setup
```shell
make install-dev-pkg
make install-dev-tools
make install-build-tools

# Used by lefthook (explained later)
make install-lint-tools

# Equivalent to pre-commit
lefthook install
```

### Go Binary Build
```shell
# Build all binaries (goreleaser)
make goreleaser

# Development build
make build

# Run build test (check for panics)
make test-runnable
```

### BPF Binary Build
```shell
make bpf-gen
```
