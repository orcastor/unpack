package upx

import (
	"bytes"
	"debug/pe"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/orcastor/unpack"
)

func TestUPX_Name(t *testing.T) {
	packer := UPX{}
	if packer.Name() != "UPX" {
		t.Errorf("Expected name 'UPX', got '%s'", packer.Name())
	}
}

func TestUPX_Detect(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		want     int
		wantErr  bool
		skipIfMissing bool
	}{
		{
			name:     "Non-existent file",
			path:     "nonexistent.exe",
			want:     UPX_VER_NONE,
			wantErr:  false,
			skipIfMissing: false,
		},
		{
			name:     "UPX packed file",
			path:     "testdata/upx_test.exe",
			want:     UPX_VER_1,
			wantErr:  false,
			skipIfMissing: true,
		},
		{
			name:     "UPX packed file - different location",
			path:     "testdata/upx_test2.exe",
			want:     UPX_VER_1,
			wantErr:  false,
			skipIfMissing: true,
		},
	}

	packer := UPX{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipIfMissing {
				if _, err := os.Stat(tt.path); os.IsNotExist(err) {
					t.Skipf("Test file %s does not exist, skipping", tt.path)
					return
				}
			}

			got := packer.Detect(tt.path)
			if got != tt.want {
				t.Errorf("UPX.Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUPX_Detect_SignatureLocations(t *testing.T) {
	packer := UPX{}
	
	// Test that detection works for files with signature at different locations
	testFiles := []string{
		"testdata/upx_test.exe",
		"testdata/upx_sig_start.exe",
		"testdata/upx_sig_end.exe",
	}

	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			continue
		}

		t.Run(filepath.Base(testFile), func(t *testing.T) {
			version := packer.Detect(testFile)
			if version == UPX_VER_NONE {
				t.Errorf("Failed to detect UPX in %s", testFile)
			} else {
				t.Logf("Detected UPX version %d in %s", version, testFile)
			}
		})
	}
}

func TestParseUPXHeader(t *testing.T) {
	// Create a mock UPX header
	headerData := make([]byte, 36)
	copy(headerData[0:4], []byte("UPX!"))
	headerData[4] = 3  // Version major
	headerData[5] = 9  // Version minor
	headerData[6] = 4  // Version revision
	headerData[7] = 1  // Format (PE)
	
	// Method, OriginalSize, CompressedSize, Filter, FilterCTO, HeaderChecksum, FileChecksum
	// Using binary.LittleEndian encoding
	headerData[8] = 0x20  // Method
	headerData[12] = 0x00
	headerData[13] = 0x10
	headerData[14] = 0x00
	headerData[15] = 0x00  // OriginalSize = 4096
	headerData[16] = 0x00
	headerData[17] = 0x05
	headerData[18] = 0x00
	headerData[19] = 0x00  // CompressedSize = 1280

	header, err := parseUPXHeader(headerData, 0)
	if err != nil {
		t.Fatalf("parseUPXHeader() error = %v", err)
	}

	if !bytes.Equal(header.Signature[:], []byte("UPX!")) {
		t.Errorf("Expected signature 'UPX!', got %v", header.Signature)
	}
	if header.VersionMajor != 3 {
		t.Errorf("Expected VersionMajor 3, got %d", header.VersionMajor)
	}
	if header.VersionMinor != 9 {
		t.Errorf("Expected VersionMinor 9, got %d", header.VersionMinor)
	}
	if header.Method != 0x20 {
		t.Errorf("Expected Method 0x20, got 0x%X", header.Method)
	}
}

func TestNRVDecompress(t *testing.T) {
	tests := []struct {
		name           string
		compressed     []byte
		decompressedSize uint32
		method         uint32
		wantErr        bool
		expectedMinLen int
	}{
		{
			name:           "Empty input",
			compressed:     []byte{},
			decompressedSize: 0,
			method:         0x20,
			wantErr:        true,
		},
		{
			name:           "Simple literal data",
			compressed:     []byte{0xFF, 0x41, 0xFF, 0x42, 0xFF, 0x43}, // Three literals
			decompressedSize: 3,
			method:         0x20,
			wantErr:        false,
			expectedMinLen: 3,
		},
		{
			name:           "Literal with match",
			compressed:     []byte{0xFF, 0x41, 0x00, 0x01, 0x00, 0x00}, // Literal 'A', then match
			decompressedSize: 3,
			method:         0x20,
			wantErr:        false,
			expectedMinLen: 2,
		},
		{
			name:           "Different method",
			compressed:     []byte{0xFF, 0x41, 0xFF, 0x42},
			decompressedSize: 2,
			method:         0x30,
			wantErr:        false,
			expectedMinLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := nrvDecompress(tt.compressed, tt.decompressedSize, tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("nrvDecompress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result) < tt.expectedMinLen {
					t.Errorf("nrvDecompress() result length = %d, want at least %d", len(result), tt.expectedMinLen)
				}
			}
		})
	}
}

func TestApplyUPXFilter(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		filterID  uint32
		filterCTO uint32
		wantLen   int
	}{
		{
			name:      "No filter",
			data:      []byte{0x41, 0x42, 0x43},
			filterID:  0,
			filterCTO: 0,
			wantLen:   3,
		},
		{
			name:      "Filter 0x26",
			data:      []byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00},
			filterID:  0x26,
			filterCTO: 0,
			wantLen:   10,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			filterID:  0x26,
			filterCTO: 0,
			wantLen:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyUPXFilter(tt.data, tt.filterID, tt.filterCTO)
			if len(result) != tt.wantLen {
				t.Errorf("applyUPXFilter() result length = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestUPX_Unpack(t *testing.T) {
	testFile := "testdata/upx_test.exe"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping unpack test", testFile)
		return
	}

	packer := UPX{}
	version := packer.Detect(testFile)
	if version == UPX_VER_NONE {
		t.Fatal("Failed to detect UPX in test file")
	}
	t.Logf("Detected UPX version: %d", version)

	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("UPX.Unpack() error = %v", err)
	}
	if reader == nil {
		t.Fatal("UPX.Unpack() returned nil reader")
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

	// Verify PE signature in unpacked data
	if n >= 64 {
		dosHeader := buf[0:64]
		peOffset := int(dosHeader[0x3C]) | (int(dosHeader[0x3D]) << 8) | (int(dosHeader[0x3E]) << 16) | (int(dosHeader[0x3F]) << 24)
		if peOffset > 0 && peOffset+4 <= n {
			peSig := buf[peOffset : peOffset+4]
			if !bytes.Equal(peSig, []byte("PE\x00\x00")) {
				t.Errorf("Invalid PE signature in unpacked data: %v", peSig)
			} else {
				t.Logf("Valid PE signature found at offset 0x%X", peOffset)
			}
		}
	}

	// Check if it's a file and close it
	if f, ok := reader.(*os.File); ok {
		defer f.Close()
		t.Logf("Unpacked file: %s", f.Name())
	}
}

func TestUPX_Unpack_VerifyPE(t *testing.T) {
	testFile := "testdata/upx_test.exe"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping verification test", testFile)
		return
	}

	packer := UPX{}
	reader, err := packer.Unpack(testFile)
	if err != nil {
		t.Fatalf("UPX.Unpack() error = %v", err)
	}
	defer func() {
		if f, ok := reader.(*os.File); ok {
			f.Close()
		}
	}()

	// Get unpacked file path
	var unpackedFilePath string
	if f, ok := reader.(*os.File); ok {
		unpackedFilePath = f.Name()
	} else {
		t.Skip("Cannot get file path for verification")
		return
	}

	// Try to parse as PE file
	peFile, err := pe.Open(unpackedFilePath)
	if err != nil {
		t.Fatalf("Failed to parse unpacked file as PE: %v", err)
	}
	defer peFile.Close()

	// Verify basic PE structure
	if peFile.FileHeader.Machine == 0 {
		t.Error("Invalid PE machine type")
	}

	// Verify sections exist
	if len(peFile.Sections) == 0 {
		t.Error("No sections found in unpacked PE file")
	} else {
		t.Logf("Found %d sections in unpacked PE file", len(peFile.Sections))
	}

	// Verify optional header
	if peFile.OptionalHeader == nil {
		t.Error("No optional header found in unpacked PE file")
	}
}

func TestUPX_MultiLayer_UPX_UPX(t *testing.T) {
	// Test case: File packed with UPX twice (UPX -> UPX -> Original)
	testFile := "testdata/upx_upx_test.exe"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping multi-layer test", testFile)
		return
	}

	// Use the main unpack library which supports multi-layer unpacking
	result, err := unpack.UnpackAll(testFile)
	if err != nil {
		t.Fatalf("unpack.UnpackAll() error = %v", err)
	}
	defer func() {
		if f, ok := result.ReaderAt.(*os.File); ok {
			f.Close()
		}
	}()

	// Verify unpacking history
	if len(result.History) < 2 {
		t.Errorf("Expected at least 2 layers, got %d", len(result.History))
	}

	// Verify all layers are UPX
	for i, layer := range result.History {
		if layer.PackerName != "UPX" {
			t.Errorf("Layer %d: expected packer 'UPX', got '%s'", i+1, layer.PackerName)
		}
		t.Logf("Layer %d: %s version %d", layer.Layer, layer.PackerName, layer.Version)
	}

	// Verify final unpacked file is valid PE
	var unpackedFilePath string
	if f, ok := result.ReaderAt.(*os.File); ok {
		unpackedFilePath = f.Name()
	} else {
		t.Skip("Cannot get file path for verification")
		return
	}

	peFile, err := pe.Open(unpackedFilePath)
	if err != nil {
		t.Fatalf("Failed to parse final unpacked file as PE: %v", err)
	}
	defer peFile.Close()

	t.Logf("Successfully unpacked %d layers, final file is valid PE", len(result.History))
}

func TestUPX_MultiLayer_Other_UPX(t *testing.T) {
	// Test case: File packed with another packer first, then UPX
	// This tests UPX as the outer layer
	testFiles := []string{
		"testdata/aspack_upx_test.exe",  // ASPack -> UPX
		"testdata/fsg_upx_test.exe",     // FSG -> UPX
	}

	// Check if any test file exists
	hasTestFile := false
	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); err == nil {
			hasTestFile = true
			break
		}
	}
	if !hasTestFile {
		t.Skip("No multi-layer test files found, skipping test")
		return
	}

	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			continue
		}

		t.Run(filepath.Base(testFile), func(t *testing.T) {
			result, err := unpack.UnpackAll(testFile)
			if err != nil {
				t.Fatalf("unpack.UnpackAll() error = %v", err)
			}
			defer func() {
				if f, ok := result.ReaderAt.(*os.File); ok {
					f.Close()
				}
			}()

			// Verify unpacking history
			if len(result.History) < 2 {
				t.Errorf("Expected at least 2 layers, got %d", len(result.History))
			}

			// Verify UPX is in the history
			foundUPX := false
			for _, layer := range result.History {
				if layer.PackerName == "UPX" {
					foundUPX = true
					t.Logf("Found UPX at layer %d", layer.Layer)
				}
			}

			if !foundUPX {
				t.Error("UPX not found in unpacking history")
			}

			// Verify final unpacked file is valid PE
			var unpackedFilePath string
			if f, ok := result.ReaderAt.(*os.File); ok {
				unpackedFilePath = f.Name()
			} else {
				t.Skip("Cannot get file path for verification")
				return
			}

			peFile, err := pe.Open(unpackedFilePath)
			if err != nil {
				t.Fatalf("Failed to parse final unpacked file as PE: %v", err)
			}
			defer peFile.Close()

			t.Logf("Successfully unpacked %d layers", len(result.History))
		})
	}
}

func TestUPX_MultiLayer_UPX_Other(t *testing.T) {
	// Test case: File packed with UPX first, then another packer
	// This tests UPX as the inner layer
	testFiles := []string{
		"testdata/upx_aspack_test.exe",  // UPX -> ASPack
		"testdata/upx_fsg_test.exe",     // UPX -> FSG
	}

	// Check if any test file exists
	hasTestFile := false
	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); err == nil {
			hasTestFile = true
			break
		}
	}
	if !hasTestFile {
		t.Skip("No multi-layer test files found, skipping test")
		return
	}

	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			continue
		}

		t.Run(filepath.Base(testFile), func(t *testing.T) {
			result, err := unpack.UnpackAll(testFile)
			if err != nil {
				t.Fatalf("unpack.UnpackAll() error = %v", err)
			}
			defer func() {
				if f, ok := result.ReaderAt.(*os.File); ok {
					f.Close()
				}
			}()

			// Verify unpacking history
			if len(result.History) < 2 {
				t.Errorf("Expected at least 2 layers, got %d", len(result.History))
			}

			// Verify first layer is UPX
			if len(result.History) > 0 && result.History[0].PackerName != "UPX" {
				t.Errorf("Expected first layer to be UPX, got '%s'", result.History[0].PackerName)
			}

			// Verify final unpacked file is valid PE
			var unpackedFilePath string
			if f, ok := result.ReaderAt.(*os.File); ok {
				unpackedFilePath = f.Name()
			} else {
				t.Skip("Cannot get file path for verification")
				return
			}

			peFile, err := pe.Open(unpackedFilePath)
			if err != nil {
				t.Fatalf("Failed to parse final unpacked file as PE: %v", err)
			}
			defer peFile.Close()

			t.Logf("Successfully unpacked %d layers, UPX was first layer", len(result.History))
		})
	}
}

func TestUPX_Unpack_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		wantErr  bool
	}{
		{
			name:     "Large file",
			testFile: "testdata/upx_large_test.exe",
			wantErr:  false,
		},
		{
			name:     "Small file",
			testFile: "testdata/upx_small_test.exe",
			wantErr:  false,
		},
		{
			name:     "File with filter",
			testFile: "testdata/upx_filtered_test.exe",
			wantErr:  false,
		},
		{
			name:     "File with different method",
			testFile: "testdata/upx_method_test.exe",
			wantErr:  false,
		},
	}

	packer := UPX{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.testFile); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist, skipping", tt.testFile)
				return
			}

			reader, err := packer.Unpack(tt.testFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("UPX.Unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && reader != nil {
				if f, ok := reader.(*os.File); ok {
					defer f.Close()
				}
			}
		})
	}
}

func TestUPX_Unpack_InvalidFiles(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		wantErr  bool
	}{
		{
			name:     "Non-PE file",
			testFile: "testdata/not_pe.txt",
			wantErr:  true,
		},
		{
			name:     "PE file without UPX",
			testFile: "testdata/normal_pe.exe",
			wantErr:  true,
		},
		{
			name:     "Corrupted UPX header",
			testFile: "testdata/corrupted_upx.exe",
			wantErr:  true,
		},
	}

	packer := UPX{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.testFile); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist, skipping", tt.testFile)
				return
			}

			reader, err := packer.Unpack(tt.testFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("UPX.Unpack() error = %v, wantErr %v", err, tt.wantErr)
			}

			if reader != nil {
				if f, ok := reader.(*os.File); ok {
					f.Close()
				}
			}
		})
	}
}

func TestRvaToFileOffset(t *testing.T) {
	testFile := "testdata/upx_test.exe"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFile)
		return
	}

	peFile, err := pe.Open(testFile)
	if err != nil {
		t.Fatalf("Failed to open PE file: %v", err)
	}
	defer peFile.Close()

	// Test RVA to file offset conversion
	if len(peFile.Sections) > 0 {
		section := peFile.Sections[0]
		testRVA := section.SectionHeader.VirtualAddress

		offset, err := rvaToFileOffset(peFile, testRVA)
		if err != nil {
			t.Fatalf("rvaToFileOffset() error = %v", err)
		}

		expectedOffset := section.SectionHeader.Offset
		if offset != expectedOffset {
			t.Errorf("rvaToFileOffset() = %v, want %v", offset, expectedOffset)
		}

		// Test invalid RVA
		_, err = rvaToFileOffset(peFile, 0xFFFFFFFF)
		if err == nil {
			t.Error("Expected error for invalid RVA, got nil")
		}
	}
}

func BenchmarkUPX_Detect(b *testing.B) {
	testFile := "testdata/upx_test.exe"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skipf("Test file %s does not exist", testFile)
		return
	}

	packer := UPX{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = packer.Detect(testFile)
	}
}

func BenchmarkUPX_Unpack(b *testing.B) {
	testFile := "testdata/upx_test.exe"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skipf("Test file %s does not exist", testFile)
		return
	}

	packer := UPX{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader, err := packer.Unpack(testFile)
		if err != nil {
			b.Fatalf("UPX.Unpack() error = %v", err)
		}
		if f, ok := reader.(*os.File); ok {
			f.Close()
		}
	}
}
