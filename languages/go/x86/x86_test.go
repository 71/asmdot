package x86

import (
	"bytes"
	"testing"
)

func TestShouldAssembleSingleRetInstruction(t *testing.T) {
	buf := new(bytes.Buffer)

	Ret(buf)

	if buf.Len() != 1 {
		t.Errorf("buf.Len() = %d; want 1", buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), []byte{0xc3}) {
		t.Errorf("buf.Bytes() is not valid")
	}
}

