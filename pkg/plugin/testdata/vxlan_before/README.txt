These eight complete GeneratorProcessResponse JSON fixtures were captured from
vxlan.go.wasm built at 7b16bbcb9dfc01922d1a43e4f5307360b6c5a259, before
migrating the builder or its configuration defaults to C-derived definitions.
TestVXLANByteCompatibility supplies the configurations in numeric file order
and compares the full response, including all packet bytes and diff/checksum
metadata. The cases cover omitted/null/zero/custom destination ports, VLAN,
checksum on/off, VNI boundaries, L2-only, weights and all sweep toggles.
The original executable and capture logs are not committed; they are retained
in the job's worktree under out/packetdefs/ as recorded in the design document.
