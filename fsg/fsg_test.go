package fsg

import (
	"io"
	"os"
	"testing"
)

func TestFSG_Detect(t *testing.T) {
	packer := FSG{}

	// Test with non-existent file
	version := packer.Detect("nonexistent.exe")
	if version != FSG_VER_NONE {
		t.Errorf("Expected FSG_VER_NONE for non-existent file, got %d", version)
	}
}

func TestFSG_Name(t *testing.T) {
	packer := FSG{}
	if packer.Name() != "FSG" {
		t.Errorf("Expected name 'FSG', got '%s'", packer.Name())
	}
}

func TestFSG_Unpack(t *testing.T) {
	testFile := "testdata/fsg_test.exe"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping unpack test", testFile)
		return
	}

	packer := FSG{}
	version := packer.Detect(testFile)
	if version == FSG_VER_NONE {
		t.Fatal("Failed to detect FSG in test file")
	}
	t.Logf("Detected FSG version: %d", version)

	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("FSG.Unpack() error = %v", err)
	}
	if reader == nil {
		t.Fatal("FSG.Unpack() returned nil reader")
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

