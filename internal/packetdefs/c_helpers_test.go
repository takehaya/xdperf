package packetdefs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/packetdefs/vxlan"
)

// Compile the actual inline C helpers on every run, so function-only header
// changes are checked even when no generated layout changes.
func TestCHeaderHelpers(t *testing.T) {
	clang, err := exec.LookPath("clang-22")
	if err != nil {
		t.Skip("LLVM 22 required")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "helpers.c")
	bin := filepath.Join(dir, "helpers")
	c := fmt.Sprintf(`#include <stdio.h>
#include %q
int main(void) {
 unsigned values[] = {0,1,0x010203,VX_VNI_MAX};
 for(unsigned i=0;i<4;i++) {
 struct vxlan_hdr h;
 vxlan_set_vni(&h,values[i]);
 if(vxlan_vni(&h)!=values[i]) return 1;
 if(fwrite(&h,1,sizeof(h),stdout)!=sizeof(h)) return 2;
 }
 return 0;
}
`, filepath.Join(root, "plugins/vxlan.c/vxlan_shared.h"))
	if err := os.WriteFile(source, []byte(c), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(clang, "-Wall", "-Werror", source, "-o", bin).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	got, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	for _, v := range []uint32{0, 1, 0x010203, vxlan.VNIMax} {
		h, err := vxlan.NewHeader(v)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, vxlan.HeaderSize)
		if err := h.MarshalTo(buf); err != nil {
			t.Fatal(err)
		}
		want = append(want, buf...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("C %x Go %x", got, want)
	}
}

func TestLayerLengths(t *testing.T) {
	if guest.EthernetHeaderLen != vxlan.EthernetLen || guest.IPv4HeaderLen != vxlan.IPv4Len || guest.UDPHeaderLen != vxlan.UDPLen {
		t.Fatal("shared C layer lengths differ from guest checksum helpers")
	}
	if vxlan.OuterLen != vxlan.EthernetLen+vxlan.IPv4Len+vxlan.UDPLen+vxlan.HeaderSize {
		t.Fatal("outer length differs from C structure")
	}
}
