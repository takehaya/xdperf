# xdperf

xdperf is a high-performance network traffic generation tool that leverages XDP (eXpress Data Path). It can operate in both client and server modes, allowing you to test network throughput and packet rate.

## install
```shell
go install github.com/takehaya/xdperf@latest
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

# Used by lefthook (explained later)
make install-lint-tools

# Equivalent to pre-commit
lefthook install
```

### Go Binary Build
```shell
# Build the application binary (xdperf)
make build

# Build the BPF binary
make bpf-gen
```
