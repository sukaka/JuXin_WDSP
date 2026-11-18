package pcapevidence

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

func TestExportPCAPRangePreservesOnlySelectedPackets(t *testing.T) {
	original := testPCAP(t, 10)
	var output bytes.Buffer
	selected, err := ExportPCAPRange(bytes.NewReader(original), &output, 2, 4)
	if err != nil || selected != 3 {
		t.Fatalf("selected=%d err=%v", selected, err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	originalReader, err := pcapgo.NewReader(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 10; i++ {
		packet, _, err := originalReader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 || i > 4 {
			continue
		}
		derived, _, err := reader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derived, packet) {
			t.Fatalf("derived packet %d differs from original", i)
		}
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatalf("derivative contains packets outside range: %v", err)
	}
}

func TestExportPCAPRangeRejectsInvalidOrTruncatedInput(t *testing.T) {
	original := testPCAP(t, 2)
	cases := []struct {
		name  string
		data  []byte
		first uint64
		last  uint64
	}{
		{name: "zero first", data: original, first: 0, last: 1},
		{name: "reversed", data: original, first: 2, last: 1},
		{name: "outside", data: original, first: 1, last: 3},
		{name: "bad magic", data: append([]byte{0}, original[1:]...), first: 1, last: 1},
		{name: "truncated", data: original[:len(original)-1], first: 1, last: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ExportPCAPRange(bytes.NewReader(tc.data), &bytes.Buffer{}, tc.first, tc.last); err == nil {
				t.Fatal("invalid derivative input was accepted")
			}
		})
	}
}
