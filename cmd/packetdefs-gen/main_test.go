package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func compiler(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("clang-22")
	if err != nil {
		t.Skip("LLVM 22 required for compiler tests")
	}
	return p
}
func fixtureManifest() manifest {
	return manifest{Package: "fixture", Header: "defs.h", Output: "generated", Types: []typeSpec{{C: "hdr", Go: "Header", Kind: "wire", Endian: "big", Fields: []fieldSpec{{"a", "A"}, {"b", "B"}, {"c", "C"}}}}, Constants: []constantSpec{{"VALUE", "Value"}}}
}
func prepare(t *testing.T, m manifest, header string) string {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "defs.h"), []byte(header), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const packedHeader = `#define VALUE (7 * 9)
struct __attribute__((packed)) hdr { unsigned char a; unsigned int b; short c[2]; };
`

func TestPackedCodecAndCheck(t *testing.T) {
	clang := compiler(t)
	for _, order := range []string{"big", "little"} {
		t.Run(order, func(t *testing.T) {
			m := fixtureManifest()
			m.Types[0].Endian = order
			dir := prepare(t, m, packedHeader)
			if err := run(dir, "manifest.json", clang, false); err != nil {
				t.Fatal(err)
			}
			if err := run(dir, "manifest.json", clang, true); err != nil {
				t.Fatal(err)
			}
			want := "[]byte{1,0x12,0x34,0x56,0x78,0xff,0xfe,0x12,0x34,0xaa}"
			if order == "little" {
				want = "[]byte{1,0x78,0x56,0x34,0x12,0xfe,0xff,0x34,0x12,0xaa}"
			}
			test := `package fixture
import("bytes";"testing")
func TestCodec(t *testing.T){
 h:=Header{A:1,B:0x12345678,C:[2]int16{-2,0x1234}}
 if HeaderSize!=9 || HeaderBOffset!=1 || Value!=63 {t.Fatal("layout")}
 dst:=bytes.Repeat([]byte{0xaa},10)
 if err:=h.MarshalTo(dst);err!=nil{t.Fatal(err)}
 if !bytes.Equal(dst,` + want + `){t.Fatalf("bytes %x",dst)}
 var got Header;if err:=got.UnmarshalFrom(dst);err!=nil{t.Fatal(err)};if got!=h{t.Fatal(got)}
 dst[0]=99;if got.A!=1{t.Fatal("aliased input")}
 before:=append([]byte(nil),dst...)
 if h.MarshalTo(dst[:8])==nil||!bytes.Equal(dst,before){t.Fatal("short write")}
 if got.UnmarshalFrom(dst[:8])==nil||got!=h{t.Fatal("short read")}
}
`
			if err := os.WriteFile(filepath.Join(dir, "generated", "codec_test.go"), []byte(test), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "test")
			cmd.Dir = filepath.Join(dir, "generated")
			cmd.Env = append(os.Environ(), "GO111MODULE=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("codec: %v\n%s", err, out)
			}
			// Check mode must report stale input and preserve committed output.
			before, err := os.ReadFile(filepath.Join(dir, "generated", "types_gen.go"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "defs.h"), []byte(strings.ReplaceAll(packedHeader, "7 * 9", "7 * 8")), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run(dir, "manifest.json", clang, true); err == nil {
				t.Fatal("stale output accepted")
			}
			after, err := os.ReadFile(filepath.Join(dir, "generated", "types_gen.go"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("check overwrote output")
			}
			if err := run(dir, "manifest.json", clang, false); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "generated", "obsolete_gen.go"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := run(dir, "manifest.json", clang, true); err == nil {
				t.Fatal("extra generated file accepted")
			}
		})
	}
}
func TestRejectedCInputs(t *testing.T) {
	clang := compiler(t)
	for _, tc := range []struct{ name, header, want string }{
		{"bitfield", `struct hdr { unsigned a:1; unsigned b; short c[2]; };`, "hdr.a: bitfield"},
		{"union", `struct hdr { unsigned char a; union { unsigned int x; unsigned char y; } b; short c[2]; };`, "hdr.b: unsupported"},
		{"pointer", `struct hdr { unsigned char a; void *b; short c[2]; };`, "hdr.b: unsupported"},
		{"flexible", `struct __attribute__((packed)) hdr { unsigned char a; unsigned b; short c[]; };`, "hdr.c: flexible"},
		{"float", `struct hdr { unsigned char a; float b; short c[2]; };`, "hdr.b: unsupported"},
		{"long", `struct hdr { unsigned char a; unsigned long b; short c[2]; };`, "hdr.b: ABI-dependent"},
		{"padding", `struct hdr { unsigned char a; unsigned int b; short c[2]; };`, "hdr.b: implicit wire padding"},
		{"overflow", `#undef VALUE
#define VALUE 2147483648ULL
struct hdr { unsigned char a,b,c; };`, "constant range"},
		{"negative overflow", `#undef VALUE
#define VALUE (-2147483647LL-2)
struct hdr { unsigned char a,b,c; };`, "constant range"},
		{"missing macro", `#undef VALUE
struct hdr { unsigned char a,b,c; };`, "VALUE"},
		{"ABI mismatch", `struct hdr { unsigned char a,b;
#ifdef __wasm__
unsigned short c;
#else
unsigned char c;
#endif
};`, "layout hdr"},
		{"integer kind mismatch", `struct hdr { unsigned char a,b;
#ifdef __wasm__
float c;
#else
signed int c;
#endif
} __attribute__((packed));`, "invalid operands"},

		{"boolean kind mismatch", `struct hdr { unsigned char a,b;
#ifdef __wasm__
_Bool c;
#else
unsigned char c;
#endif
};`, "boolean kind hdr.c"},

		{"signedness mismatch", `struct hdr { unsigned char a,b;
#ifdef __wasm__
signed char c;
#else
unsigned char c;
#endif
};`, "integer hdr.c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := prepare(t, fixtureManifest(), "#define VALUE 1\n"+tc.header)
			err := run(dir, "manifest.json", clang, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}
func TestMissingRetention(t *testing.T) {
	clang := compiler(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "missing.c")
	obj := filepath.Join(dir, "missing.o")
	if err := os.WriteFile(src, []byte("enum xd_constants {xd_c0=1,xd_a0=1}; enum xd_constants keep;\nstruct hdr { unsigned char a,b,c; };\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := command(clang, "-target", "bpfel", "-g", "-O2", "-c", src, "-o", obj); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	spec, err := btf.LoadSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extract(spec, fixtureManifest()); err == nil || !strings.Contains(err.Error(), "hdr retention") {
		t.Fatalf("%v", err)
	}
}
func TestManifestNames(t *testing.T) {
	for _, mutate := range []func(*manifest){
		func(m *manifest) { m.Types[0].Go = "HeaderSize"; m.Constants[0].Go = "HeaderSize" },
		func(m *manifest) { m.Types[0].Fields[0].Go = "MarshalTo" },
		func(m *manifest) { m.Types[0].Fields[0].Go = "type" },
		func(m *manifest) { m.Constants[0].Go = "HeaderAOffset" },
		func(m *manifest) { m.Types[0].Endian = "" },
		func(m *manifest) { m.Types[0].Kind = "unknown" },
		func(m *manifest) { m.Types[0].C = "hdr;" },
	} {
		m := fixtureManifest()
		mutate(&m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readManifest(raw); err == nil {
			t.Fatal("invalid manifest accepted", string(raw))
		}
	}
}

func TestBpf2goExtraction(t *testing.T) {
	clang := compiler(t)
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "internal/packetdefs/vxlan/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "defs.c")
	if err := os.WriteFile(src, []byte(translation(m, filepath.Join(repo, m.Header))), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", "github.com/cilium/ebpf/cmd/bpf2go", "-cc", clang, "-no-global-types", "-no-strip", "-target", "bpfel,bpfeb", "-type", "vxlan_hdr", "-type", "vx_inner_key", "-type", "xd_constants", "-output-dir", dir, "probe", src, "--", "-O2", "-g")
	cmd.Env = append(os.Environ(), "GOPACKAGE=probe")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bpf2go: %v\n%s", err, out)
	}
	for _, target := range []string{"bpfel", "bpfeb"} {
		data, err := os.ReadFile(filepath.Join(dir, "probe_"+target+".go"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "[3]uint8") || !strings.Contains(string(data), "4789") {
			t.Fatalf("missing extracted fields/constants: %s", data)
		}
	}
}

func TestRegenerationInputChanges(t *testing.T) {
	clang := compiler(t)
	for _, kind := range []string{"array length", "manifest name", "included macro", "missing file"} {
		t.Run(kind, func(t *testing.T) {
			m := fixtureManifest()
			header := packedHeader
			if kind == "included macro" {
				header = "#include \"nested.h\"\n" + strings.ReplaceAll(header, "#define VALUE (7 * 9)", "")
			}
			dir := prepare(t, m, header)
			if err := os.WriteFile(filepath.Join(dir, "nested.h"), []byte("#define VALUE 63\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run(dir, "manifest.json", clang, false); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "array length":
				if err := os.WriteFile(filepath.Join(dir, "defs.h"), []byte(strings.ReplaceAll(header, "c[2]", "c[3]")), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest name":
				m.Types[0].Fields[1].Go = "Renamed"
				raw, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "included macro":
				if err := os.WriteFile(filepath.Join(dir, "nested.h"), []byte("#define VALUE (64 - 1)\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing file":
				if err := os.Remove(filepath.Join(dir, "generated", "codec_gen.go")); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(dir, "manifest.json", clang, true); err == nil {
				t.Fatalf("%s did not invalidate generated output", kind)
			}
			if err := run(dir, "manifest.json", clang, false); err != nil {
				t.Fatal(err)
			}
			if err := run(dir, "manifest.json", clang, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
