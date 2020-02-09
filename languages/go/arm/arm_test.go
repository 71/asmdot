package arm

import (
	"bytes"
	"testing"
)

func TestShouldEncodeSingleCpsInstruction(t *testing.T) {
	buf := new(bytes.Buffer)

	Cps(buf, USRMode)

	if buf.Len() != 4 {
		t.Errorf("buf.Len() = %d; want 4", buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x10, 0x00, 0x02, 0xf1}) {
		t.Errorf("buf.Bytes() is not valid")
	}
}

