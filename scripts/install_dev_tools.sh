#!/bin/bash
# Install development tools
set -e
go install golang.org/x/tools/cmd/goimports@v0.38.0
go install go.uber.org/nilaway/cmd/nilaway@latest