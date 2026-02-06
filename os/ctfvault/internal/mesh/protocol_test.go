package mesh

import (
	"bytes"
	"strings"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	buf := &bytes.Buffer{}
	hdr := Header{Version: 1, Op: "send", Name: "file.txt", Size: 123}
	if err := writeHeader(buf, hdr); err != nil {
		t.Fatalf("writeHeader error: %v", err)
	}
	out, err := readHeader(buf)
	if err != nil {
		t.Fatalf("readHeader error: %v", err)
	}
	if out.Op != hdr.Op || out.Name != hdr.Name || out.Size != hdr.Size {
		t.Fatalf("unexpected header: %#v", out)
	}
}

func TestHeaderTooLarge(t *testing.T) {
	buf := &bytes.Buffer{}
	hdr := Header{Version: 1, Op: "send", Name: strings.Repeat("a", maxHeaderSize)}
	if err := writeHeader(buf, hdr); err == nil {
		t.Fatal("expected error for large header")
	}
}

func TestHeaderInvalidSize(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := readHeader(buf); err == nil {
		t.Fatal("expected error for invalid header size")
	}
}
