package winupack

import (
	"io"
	"os"
	"testing"
)

func TestWinUpack_Detect(t *testing.T) {
	packer := WinUpack{}

	version := packer.Detect("nonexistent.exe")
	if version != WINUPACK_VER_NONE {
		t.Errorf("Expected WINUPACK_VER_NONE for non-existent file, got %d", version)
	}
}

func TestWinUpack_Name(t *testing.T) {
	packer := WinUpack{}
	if packer.Name() != "WinUpack" {
		t.Errorf("Expected name 'WinUpack', got '%s'", packer.Name())
	}
}

func TestWinUpack_Unpack(t *testing.T) {
	testFile := "testdata/winupack_test.exe"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping unpack test", testFile)
		return
	}

	packer := WinUpack{}
	version := packer.Detect(testFile)
	if version == WINUPACK_VER_NONE {
		t.Fatal("Failed to detect WinUpack in test file")
	}
	t.Logf("Detected WinUpack version: %d", version)

	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("WinUpack.Unpack() error = %v", err)
	}
	if reader == nil {
		t.Fatal("WinUpack.Unpack() returned nil reader")
	}

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

	if f, ok := reader.(*os.File); ok {
		defer f.Close()
		t.Logf("Unpacked file: %s", f.Name())
	}
}

