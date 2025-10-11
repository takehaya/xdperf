#!/usr/bin/env bash
# Library of installer helpers for lint tools

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a tool
# how to use:
#   install_tool "lefthook" "go install github.com/evilmartians/lefthook@latest"
install_tool() {
    local tool="$1"
    local install_cmd="$2"

    if command_exists "$tool"; then
        echo "✓ ${tool} is already installed"
        return 0
    fi

    echo "Installing ${tool}..."
    # shellcheck disable=SC2086
    eval ${install_cmd}
    if command_exists "$tool"; then
        echo "✓ ${tool} installed successfully"
        return 0
    fi

    echo "✗ Failed to install ${tool}"
    return 1
}

# This file is intended to be sourced as a library
# If executed directly, do nothing and exit
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    exit 0
fi
