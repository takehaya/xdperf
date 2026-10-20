// packetdefs-gen extracts a deliberately limited packet schema from C/BTF.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type fieldSpec struct {
	C  string `json:"c"`
	Go string `json:"go"`
}
type typeSpec struct {
	C      string      `json:"c"`
	Go     string      `json:"go"`
	Kind   string      `json:"kind"`
	Endian string      `json:"endian,omitempty"`
	Fields []fieldSpec `json:"fields"`
}
type constantSpec struct {
	C  string `json:"c"`
	Go string `json:"go"`
}
type manifest struct {
	Package   string         `json:"package"`
	Header    string         `json:"header"`
	Output    string         `json:"output"`
	Types     []typeSpec     `json:"types"`
	Constants []constantSpec `json:"constants"`
}
type field struct {
	C      string
	Go     string
	Offset uint32
	Size   uint32
	Width  uint32
	Count  uint32
	Signed bool
}
type record struct {
	C      string
	Go     string
	Kind   string
	Endian string
	Size   uint32
	Align  uint32
	Fields []field
}
type constant struct {
	Name  string
	Value int64
}
type schema struct {
	Records   []record
	Constants []constant
}

func main() {
	repo := flag.String("repo", ".", "repository root")
	input := flag.String("manifest", "internal/packetdefs/vxlan/manifest.json", "manifest relative to repository")
	clang := flag.String("clang", "clang-22", "LLVM 22 compiler")
	check := flag.Bool("check", false, "compare generated file set and contents without writing")
	flag.Parse()
	if err := run(*repo, *input, *clang, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(clang string, args ...string) ([]byte, error) {
	out, err := exec.Command(clang, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w\n%s", clang, strings.Join(args, " "), err, out)
	}
	return out, nil
}
func readManifest(data []byte) (manifest, error) {
	var m manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, fmt.Errorf("manifest has trailing data")
	}
	names := map[string]bool{}
	add := func(s string) error {
		if !token.IsIdentifier(s) || !token.IsExported(s) || names[s] {
			return fmt.Errorf("invalid or duplicate Go name %q", s)
		}
		names[s] = true
		return nil
	}
	if !token.IsIdentifier(m.Package) || m.Package == "_" || m.Header == "" || m.Output == "" || len(m.Types) == 0 {
		return m, fmt.Errorf("incomplete manifest")
	}
	for _, t := range m.Types {
		if !cIdentifier(t.C) {
			return m, fmt.Errorf("invalid C type %q", t.C)
		}
		if t.Kind != "wire" && t.Kind != "internal" {
			return m, fmt.Errorf("%s: explicit wire/internal kind required", t.C)
		}
		if (t.Kind == "wire" && t.Endian != "big" && t.Endian != "little") || (t.Kind == "internal" && t.Endian != "") {
			return m, fmt.Errorf("%s: invalid endian policy", t.C)
		}
		for _, s := range []string{t.Go, t.Go + "Size", t.Go + "Align"} {
			if err := add(s); err != nil {
				return m, err
			}
		}
		local := map[string]bool{"MarshalTo": true, "UnmarshalFrom": true}
		cfields := map[string]bool{}
		for _, f := range t.Fields {
			if !cIdentifier(f.C) || !token.IsIdentifier(f.Go) || !token.IsExported(f.Go) || local[f.Go] || cfields[f.C] {
				return m, fmt.Errorf("%s.%s: invalid or duplicate field", t.C, f.C)
			}
			local[f.Go] = true
			cfields[f.C] = true
			for _, suffix := range []string{"Offset", "Size"} {
				if err := add(t.Go + f.Go + suffix); err != nil {
					return m, err
				}
			}
		}
	}
	for _, c := range m.Constants {
		if !cIdentifier(c.C) {
			return m, fmt.Errorf("invalid C constant %q", c.C)
		}
		if err := add(c.Go); err != nil {
			return m, err
		}
	}
	return m, nil
}
func cIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (i <= 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func translation(m manifest, header string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#include %q\n", filepath.ToSlash(header))
	b.WriteString("enum xd_constants {\n")
	for i, c := range m.Constants {
		fmt.Fprintf(&b, "xd_c%d = %s,\n", i, c.C)
	}
	for i, t := range m.Types {
		fmt.Fprintf(&b, "xd_a%d = __alignof__(struct %s),\n", i, t.C)
	}
	b.WriteString("};\nenum xd_constants xd_keep_constants;\n")
	for i, t := range m.Types {
		fmt.Fprintf(&b, "struct %s xd_keep_%d;\n", t.C, i)
	}
	for _, c := range m.Constants {
		fmt.Fprintf(&b, "_Static_assert(((%s) < 0 ? (long long)(%s) >= (-2147483647LL-1) : (unsigned long long)(%s) <= 2147483647ULL), \"constant range: %s\");\n", c.C, c.C, c.C, c.C)
	}
	return b.String()
}
func integer(t btf.Type) (*btf.Int, error) {
	// Preserve alias origins long enough to reject pointer-width-dependent names.
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			if v.Name == "size_t" || v.Name == "ptrdiff_t" {
				return nil, fmt.Errorf("ABI-dependent typedef %s", v.Name)
			}
			t = v.Type
		case *btf.Const:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Restrict:
			t = v.Type
		default:
			goto resolved
		}
	}
resolved:
	v, ok := t.(*btf.Int)
	if !ok {
		return nil, fmt.Errorf("unsupported type %T", t)
	}
	if v.Name == "long" || v.Name == "long int" || v.Name == "unsigned long" || v.Name == "long unsigned int" || v.Name == "unsigned long int" {
		return nil, fmt.Errorf("ABI-dependent integer %s", v.Name)
	}
	if v.Size != 1 && v.Size != 2 && v.Size != 4 && v.Size != 8 {
		return nil, fmt.Errorf("unsupported integer width %d", v.Size)
	}
	if v.Encoding != btf.Unsigned && v.Encoding != btf.Signed {
		return nil, fmt.Errorf("unsupported integer encoding %s", v.Encoding)
	}
	return v, nil
}
func extract(spec *btf.Spec, m manifest) (schema, error) {
	var s schema
	var e *btf.Enum
	if err := spec.TypeByName("xd_constants", &e); err != nil {
		return s, fmt.Errorf("constant retention: %w", err)
	}
	if e.Size != 4 {
		return s, fmt.Errorf("bridge enum width %d", e.Size)
	}
	values := map[string]uint64{}
	for _, v := range e.Values {
		values[v.Name] = v.Value
	}
	for i, c := range m.Constants {
		v, ok := values[fmt.Sprintf("xd_c%d", i)]
		if !ok {
			return s, fmt.Errorf("missing constant %s", c.C)
		}
		s.Constants = append(s.Constants, constant{c.Go, int64(int32(v))})
	}
	for i, t := range m.Types {
		var st *btf.Struct
		if err := spec.TypeByName(t.C, &st); err != nil {
			return s, fmt.Errorf("%s retention: %w", t.C, err)
		}
		align, ok := values[fmt.Sprintf("xd_a%d", i)]
		if !ok || align == 0 {
			return s, fmt.Errorf("%s: missing alignment", t.C)
		}
		r := record{C: t.C, Go: t.Go, Kind: t.Kind, Endian: t.Endian, Size: st.Size, Align: uint32(align)}
		if len(st.Members) != len(t.Fields) {
			return s, fmt.Errorf("%s: manifest must name all %d fields", t.C, len(st.Members))
		}
		var end uint32
		for j, mem := range st.Members {
			path := t.C + "." + mem.Name
			if mem.Name != t.Fields[j].C || mem.Name == "" {
				return s, fmt.Errorf("%s: field order/name differs from manifest", path)
			}
			if mem.BitfieldSize != 0 || mem.Offset%8 != 0 {
				return s, fmt.Errorf("%s: bitfield unsupported", path)
			}
			typ := mem.Type
			var count uint32
			if a, ok := btf.UnderlyingType(typ).(*btf.Array); ok {
				if a.Nelems == 0 {
					return s, fmt.Errorf("%s: flexible array unsupported", path)
				}
				count = a.Nelems
				typ = a.Type
			}
			n, err := integer(typ)
			if err != nil {
				return s, fmt.Errorf("%s: %w", path, err)
			}
			size := uint64(n.Size)
			if count > 0 {
				size *= uint64(count)
			}
			off := uint32(mem.Offset / 8)
			if size > uint64(st.Size) || uint64(off)+size > uint64(st.Size) || off < end {
				return s, fmt.Errorf("%s: invalid bounds", path)
			}
			if t.Kind == "wire" && off != end {
				return s, fmt.Errorf("%s: implicit wire padding", path)
			}
			r.Fields = append(r.Fields, field{mem.Name, t.Fields[j].Go, off, uint32(size), n.Size, count, n.Encoding == btf.Signed})
			end = off + uint32(size)
		}
		if t.Kind == "wire" && end != st.Size {
			return s, fmt.Errorf("%s: implicit wire tail padding", t.C)
		}
		s.Records = append(s.Records, r)
	}
	return s, nil
}
func assertions(s schema, m manifest) string {
	var b strings.Builder
	for _, r := range s.Records {
		fmt.Fprintf(&b, "_Static_assert(sizeof(struct %s)==%d && __alignof__(struct %s)==%d, \"layout %s\");\n", r.C, r.Size, r.C, r.Align, r.C)
		for _, f := range r.Fields {
			expr := fmt.Sprintf("((struct %s *)0)->%s", r.C, f.C)
			fmt.Fprintf(&b, "_Static_assert(__builtin_offsetof(struct %s,%s)==%d && sizeof(%s)==%d, \"field %s.%s\");\n", r.C, f.C, f.Offset, expr, f.Size, r.C, f.C)
			if f.Count > 0 {
				expr += "[0]"
			}
			fmt.Fprintf(&b, "_Static_assert(!__builtin_types_compatible_p(__typeof__(%s), _Bool), \"boolean kind %s.%s\");\n", expr, r.C, f.C)
			fmt.Fprintf(&b, "_Static_assert((((__typeof__(%s))0 | 1) == 1), \"integer kind %s.%s\");\n", expr, r.C, f.C)
			fmt.Fprintf(&b, "_Static_assert(sizeof(%s)==%d && (((__typeof__(%s))-1 < (__typeof__(%s))0)==%d), \"integer %s.%s\");\n", expr, f.Width, expr, expr, boolInt(f.Signed), r.C, f.C)
		}
	}
	for i, c := range s.Constants {
		fmt.Fprintf(&b, "_Static_assert(%s == (%dLL), \"constant %s\");\n", m.Constants[i].C, c.Value, c.Name)
	}
	return b.String()
}
func goType(f field) string {
	v := "uint"
	if f.Signed {
		v = "int"
	}
	v += fmt.Sprint(f.Width * 8)
	if f.Count > 0 {
		return fmt.Sprintf("[%d]%s", f.Count, v)
	}
	return v
}
func emit(s schema, m manifest) (map[string][]byte, error) {
	var types, codec strings.Builder
	for _, b := range []*strings.Builder{&types, &codec} {
		fmt.Fprintf(b, "// Code generated by packetdefs-gen; DO NOT EDIT.\npackage %s\n\n", m.Package)
	}
	wire, multibyte := false, false
	for _, r := range s.Records {
		if r.Kind == "wire" {
			wire = true
			for _, f := range r.Fields {
				if f.Width > 1 {
					multibyte = true
				}
			}
		}
	}
	if wire {
		codec.WriteString("import (\"fmt\"\n")
		if multibyte {
			codec.WriteString("\"encoding/binary\"\n")
		}
		codec.WriteString(")\n")
	}
	for _, c := range s.Constants {
		fmt.Fprintf(&types, "const %s = %d\n", c.Name, c.Value)
	}
	for _, r := range s.Records {
		fmt.Fprintf(&types, "// %s is a value type; its Go memory layout is not a C ABI.\ntype %s struct {\n", r.Go, r.Go)
		for _, f := range r.Fields {
			fmt.Fprintf(&types, "%s %s\n", f.Go, goType(f))
		}
		types.WriteString("}\n")
		fmt.Fprintf(&types, "const (%sSize = %d; %sAlign = %d\n", r.Go, r.Size, r.Go, r.Align)
		for _, f := range r.Fields {
			fmt.Fprintf(&types, "%s%sOffset = %d; %s%sSize = %d\n", r.Go, f.Go, f.Offset, r.Go, f.Go, f.Size)
		}
		types.WriteString(")\n")
		if r.Kind != "wire" {
			continue
		}
		order := "BigEndian"
		if r.Endian == "little" {
			order = "LittleEndian"
		}
		for _, marshal := range []bool{true, false} {
			if marshal {
				fmt.Fprintf(&codec, "func (v %s) MarshalTo(buf []byte) error {\n", r.Go)
			} else {
				fmt.Fprintf(&codec, "func (v *%s) UnmarshalFrom(buf []byte) error {\n", r.Go)
			}
			fmt.Fprintf(&codec, "if len(buf)<%sSize { return fmt.Errorf(\"%s: need %%d bytes, got %%d\", %sSize, len(buf)) }\n", r.Go, r.Go, r.Go)
			for _, f := range r.Fields {
				access := "v." + f.Go
				offset := fmt.Sprint(f.Offset)
				if f.Count > 0 {
					fmt.Fprintf(&codec, "for i := range %s {\n", access)
					access += "[i]"
					offset += fmt.Sprintf("+i*%d", f.Width)
				}
				plain := f
				plain.Count = 0
				if f.Width == 1 {
					if marshal {
						fmt.Fprintf(&codec, "buf[%s] = byte(%s)\n", offset, access)
					} else {
						fmt.Fprintf(&codec, "%s = %s(buf[%s])\n", access, goType(plain), offset)
					}
				} else {
					slice := fmt.Sprintf("buf[%s: %s+%d]", offset, offset, f.Width)
					if marshal {
						fmt.Fprintf(&codec, "binary.%s.PutUint%d(%s, uint%d(%s))\n", order, f.Width*8, slice, f.Width*8, access)
					} else {
						fmt.Fprintf(&codec, "%s = %s(binary.%s.Uint%d(%s))\n", access, goType(plain), order, f.Width*8, slice)
					}
				}
				if f.Count > 0 {
					codec.WriteString("}\n")
				}
			}
			codec.WriteString("return nil\n}\n")
		}
	}
	out := map[string][]byte{}
	for name, b := range map[string]*strings.Builder{"types_gen.go": &types, "codec_gen.go": &codec} {
		v, err := format.Source([]byte(b.String()))
		if err != nil {
			return nil, fmt.Errorf("format %s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}
func run(repo, input, clang string, check bool) error {
	repo, err := filepath.Abs(repo)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(repo, input))
	if err != nil {
		return err
	}
	m, err := readManifest(raw)
	if err != nil {
		return err
	}
	version, err := command(clang, "--version")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.SplitN(string(version), "\n", 2)[0], "version 22.") {
		return fmt.Errorf("LLVM 22 required")
	}
	tmp, err := os.MkdirTemp("", "packetdefs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src := translation(m, filepath.Join(repo, m.Header))
	source := filepath.Join(tmp, "defs.c")
	if err := os.WriteFile(source, []byte(src), 0600); err != nil {
		return err
	}
	var s schema
	for i, target := range []string{"bpfel", "bpfeb"} {
		obj := filepath.Join(tmp, target+".o")
		if _, err := command(clang, "-target", target, "-std=c11", "-g", "-O2", "-Wall", "-Werror", "-c", source, "-o", obj); err != nil {
			return err
		}
		spec, err := btf.LoadSpec(obj)
		if err != nil {
			return err
		}
		got, err := extract(spec, m)
		if err != nil {
			return err
		}
		if i == 0 {
			s = got
		} else if !reflect.DeepEqual(s, got) {
			return fmt.Errorf("bpfel/bpfeb schema mismatch")
		}
	}
	src += "\n" + assertions(s, m)
	if err := os.WriteFile(source, []byte(src), 0600); err != nil {
		return err
	}
	if _, err := command(clang, "-target", "wasm32", "-std=c11", "-Wall", "-Werror", "-c", source, "-o", filepath.Join(tmp, "wasm.o")); err != nil {
		return err
	}
	out, err := emit(s, m)
	if err != nil {
		return err
	}
	// Preprocessing captures transitive include contents without paths or dates.
	pp, err := command(clang, "-target", "bpfel", "-E", "-P", source)
	if err != nil {
		return err
	}
	meta := struct {
		Format         int
		InputSHA256    string
		ManifestSHA256 string
		Schema         schema
	}{1, fmt.Sprintf("%x", sha256.Sum256(pp)), fmt.Sprintf("%x", sha256.Sum256(raw)), s}
	out["layout_gen.json"], err = json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	out["layout_gen.json"] = append(out["layout_gen.json"], '\n')
	return writeOutput(filepath.Join(repo, m.Output), out, check)
}
func writeOutput(dir string, out map[string][]byte, check bool) error {
	// Validate the entire owned file set before writing or comparing anything.
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "_gen.") {
			if _, ok := out[e.Name()]; !ok {
				return fmt.Errorf("unexpected generated file %s", e.Name())
			}
		}
	}
	if check {
		for _, name := range []string{"types_gen.go", "codec_gen.go", "layout_gen.json"} {
			want := out[name]
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.Equal(got, want) {
				return fmt.Errorf("stale generated file %s; run make packetdefs-gen", filepath.Join(dir, name))
			}
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, name := range []string{"types_gen.go", "codec_gen.go", "layout_gen.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), out[name], 0644); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
