package aspack

import (
	"io"
	"os"
	"testing"
)

func TestASPack_Detect(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		a    ASPack
		args args
		want int
	}{
		{
			name: "Test ASPack 2.1",
			a:    ASPack{},
			args: args{path: "testdata/aspack_test.exe"},
			want: ASPACK_VER_21, // aspack_test.exe is packed with ASPack 2.1
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Detect(tt.args.path); got != tt.want {
				t.Errorf("ASPack.Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestASPack_Unpack(t *testing.T) {
	testFile := "testdata/aspack_test.exe"

	// Check if test file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping unpack test", testFile)
		return
	}

	// Test detection first
	packer := ASPack{}
	version := packer.Detect(testFile)
	if version == ASPACK_VER_NONE {
		t.Fatal("Failed to detect ASPack in test file")
	}
	t.Logf("Detected ASPack version: %d", version)

	// Test unpacking
	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("ASPack.Unpack() error = %v", err)
	}
	if reader == nil {
		t.Fatal("ASPack.Unpack() returned nil reader")
	}

	// Verify we can read from the unpacked data
	buf := make([]byte, 1024)
	n, err := reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read from unpacked data: %v", err)
	}
	if n == 0 {
		t.Error("Unpacked data is empty")
	} else {
		t.Logf("Successfully read %d bytes from unpacked data", n)
	}

	// Check if it's a file and close it
	if f, ok := reader.(*os.File); ok {
		defer f.Close()
		t.Logf("Unpacked file: %s", f.Name())
	}
}
