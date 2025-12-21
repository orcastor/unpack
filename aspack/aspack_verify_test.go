package aspack

import (
	"debug/pe"
	"io"
	"os"
	"testing"
)

// TestASPack_VerifyUnpacked verifies that the unpacked file is correct
func TestASPack_VerifyUnpacked(t *testing.T) {
	testFile := "testdata/aspack_test.exe"

	// Check if test file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping verification test", testFile)
		return
	}

	// Test detection first
	packer := ASPack{}
	version := packer.Detect(testFile)
	if version == ASPACK_VER_NONE {
		t.Fatal("Failed to detect ASPack in test file")
	}
	t.Logf("Detected ASPack version: %d", version)

	// Get original file info for comparison
	originalPeFile, err := pe.Open(testFile)
	if err != nil {
		t.Fatalf("Failed to open original PE file: %v", err)
	}
	defer originalPeFile.Close()

	var originalOEP uint32
	switch optHdr := originalPeFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		originalOEP = optHdr.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		originalOEP = optHdr.AddressOfEntryPoint
	}
	t.Logf("Original Entry Point (packed): 0x%X", originalOEP)

	// Test unpacking
	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("ASPack.Unpack() error = %v", err)
	}
	if reader == nil {
		t.Fatal("ASPack.Unpack() returned nil reader")
	}

	// Get the unpacked file path
	var unpackedFilePath string
	if f, ok := reader.(*os.File); ok {
		unpackedFilePath = f.Name()
		defer f.Close()
		t.Logf("Unpacked file: %s", unpackedFilePath)
	} else {
		// If it's not a file, save it to a temporary file for verification
		tmpFile, err := os.CreateTemp("", "unpacked_verify_*.exe")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		unpackedFilePath = tmpFile.Name()

		// Copy reader data to file
		buf := make([]byte, 64*1024)
		offset := int64(0)
		for {
			n, err := reader.ReadAt(buf, offset)
			if n > 0 {
				if _, writeErr := tmpFile.Write(buf[:n]); writeErr != nil {
					t.Fatalf("Failed to write to temp file: %v", writeErr)
				}
				offset += int64(n)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("Failed to read from unpacked data: %v", err)
			}
		}
		tmpFile.Close()
	}

	// Verify unpacked file is a valid PE file
	unpackedPeFile, err := pe.Open(unpackedFilePath)
	if err != nil {
		t.Fatalf("Unpacked file is not a valid PE file: %v", err)
	}
	defer unpackedPeFile.Close()

	t.Log("✓ Unpacked file is a valid PE file")

	// Verify entry point (OEP) has changed
	var unpackedOEP uint32
	switch optHdr := unpackedPeFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		unpackedOEP = optHdr.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		unpackedOEP = optHdr.AddressOfEntryPoint
	}
	t.Logf("Unpacked Entry Point (OEP): 0x%X", unpackedOEP)

	if unpackedOEP == originalOEP {
		t.Errorf("Entry point was not updated! OEP (0x%X) should be different from packed EP (0x%X)", unpackedOEP, originalOEP)
	} else {
		t.Logf("✓ Entry point updated from 0x%X to 0x%X", originalOEP, unpackedOEP)
	}

	// Verify OEP is in a valid section
	oepInSection := false
	for _, section := range unpackedPeFile.Sections {
		if section.SectionHeader.VirtualAddress <= unpackedOEP &&
			unpackedOEP < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
			oepInSection = true
			t.Logf("✓ OEP is in section: %s", section.Name)
			break
		}
	}
	if !oepInSection {
		t.Errorf("OEP (0x%X) is not in any section!", unpackedOEP)
	}

	// Verify import table exists and is valid
	switch optHdr := unpackedPeFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(optHdr.DataDirectory) > 1 {
			importTableRVA := optHdr.DataDirectory[1].VirtualAddress
			importTableSize := optHdr.DataDirectory[1].Size
			if importTableRVA == 0 {
				t.Log("⚠ Import table RVA is 0 (may be valid for some executables)")
			} else {
				t.Logf("✓ Import table found at RVA: 0x%X, Size: 0x%X", importTableRVA, importTableSize)
			}
		}
	case *pe.OptionalHeader64:
		if len(optHdr.DataDirectory) > 1 {
			importTableRVA := optHdr.DataDirectory[1].VirtualAddress
			importTableSize := optHdr.DataDirectory[1].Size
			if importTableRVA == 0 {
				t.Log("⚠ Import table RVA is 0 (may be valid for some executables)")
			} else {
				t.Logf("✓ Import table found at RVA: 0x%X, Size: 0x%X", importTableRVA, importTableSize)
			}
		}
	}

	// Verify sections
	t.Logf("Unpacked file has %d sections:", len(unpackedPeFile.Sections))
	for i, section := range unpackedPeFile.Sections {
		t.Logf("  Section %d: %s, RVA: 0x%X, Size: 0x%X", i+1, section.Name, section.SectionHeader.VirtualAddress, section.SectionHeader.VirtualSize)
	}

	// Verify file size is reasonable
	fileInfo, err := os.Stat(unpackedFilePath)
	if err != nil {
		t.Fatalf("Failed to stat unpacked file: %v", err)
	}
	unpackedSize := fileInfo.Size()
	originalInfo, _ := os.Stat(testFile)
	originalSize := originalInfo.Size()

	t.Logf("Original file size: %d bytes", originalSize)
	t.Logf("Unpacked file size: %d bytes", unpackedSize)

	// Unpacked file should typically be larger than or equal to original
	// (decompressed data is usually larger than compressed)
	if unpackedSize < originalSize/2 {
		t.Errorf("Unpacked file size (%d) seems too small compared to original (%d)", unpackedSize, originalSize)
	} else {
		t.Log("✓ File size is reasonable")
	}

	// Try to read import descriptors
	imports, err := unpackedPeFile.ImportedSymbols()
	if err != nil {
		t.Logf("⚠ Could not read imported symbols: %v (this may be normal)", err)
	} else {
		t.Logf("✓ Found %d imported symbols", len(imports))
		if len(imports) > 0 {
			t.Logf("  First few imports: %v", imports[:min(5, len(imports))])
		}
	}

	// Verify DOS header
	dosHeader := make([]byte, 64)
	unpackedFile, err := os.Open(unpackedFilePath)
	if err != nil {
		t.Fatalf("Failed to open unpacked file: %v", err)
	}
	defer unpackedFile.Close()

	_, err = unpackedFile.ReadAt(dosHeader, 0)
	if err != nil {
		t.Fatalf("Failed to read DOS header: %v", err)
	}

	// Check DOS signature "MZ"
	if dosHeader[0] == 'M' && dosHeader[1] == 'Z' {
		t.Log("✓ DOS header is valid (MZ signature)")
	} else {
		t.Errorf("Invalid DOS header: expected MZ, got %c%c", dosHeader[0], dosHeader[1])
	}

	// Check PE signature offset
	peOffset := uint32(dosHeader[0x3C]) | (uint32(dosHeader[0x3D]) << 8) | (uint32(dosHeader[0x3E]) << 16) | (uint32(dosHeader[0x3F]) << 24)
	if peOffset > 0 && peOffset < uint32(unpackedSize) {
		peSig := make([]byte, 4)
		_, err = unpackedFile.ReadAt(peSig, int64(peOffset))
		if err == nil && peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0 {
			t.Log("✓ PE signature is valid")
		} else {
			t.Errorf("Invalid PE signature at offset 0x%X", peOffset)
		}
	} else {
		t.Errorf("Invalid PE offset: 0x%X", peOffset)
	}

	t.Log("✓ All basic verifications passed!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

