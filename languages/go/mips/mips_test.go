package mips

import (
	"bytes"
	"testing"
)

func TestShouldAssembleSingleAddiInstruction(t *testing.T) {
	buf := new(bytes.Buffer)

	Addi(buf, T1, T2, 0)

	if buf.Len() != 4 {
		t.Errorf("buf.Len() = %d; want 4", buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x00, 0x00, 0x49, 0x21}) {
		t.Errorf("buf.Bytes() is not valid")
	}
}

