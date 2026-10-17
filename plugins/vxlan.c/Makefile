# Builds vxlan.c.wasm with clang for wasm32 (no libc). CLANG can point at any
# clang with the WebAssembly target and wasm-ld (lld) installed.
CLANG ?= clang
OUT ?= ../../out/bin/vxlan.c.wasm

$(OUT): main.c vxlan_shared.h
	$(CLANG) --target=wasm32 -O2 -nostdlib -ffreestanding -Wall -Wextra \
		-Wl,--no-entry -Wl,--export-dynamic -Wl,--allow-undefined -o $@ main.c
