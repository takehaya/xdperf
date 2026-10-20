// Package packetdefs registers host-only C-to-Go generation.
package packetdefs

//go:generate go run ../../cmd/packetdefs-gen -repo ../.. -manifest internal/packetdefs/vxlan/manifest.json
