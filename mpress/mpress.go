package mpress

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"

	"github.com/orcastor/unpack"
)

func init() {
	unpack.RegisterFormat("MPRESS", MPRESS{})
}

const (
	MPRESS_VER_NONE = 0 + iota
	MPRESS_VER_1
	MPRESS_VER_2
)

// MPRESS signatures
var mpressSignatures = [][]byte{
	[]byte("MPRESS"),
	[]byte("MPRESS1"),
	[]byte("MPRESS2"),
}

type MPRESS struct{}

func (MPRESS) Name() string {
	return "MPRESS"
}

// Detect checks if the file is packed with MPRESS
func (MPRESS) Detect(path string) int {
	peFile, err := pe.Open(path)
	if err != nil {
		return MPRESS_VER_NONE
	}
	defer peFile.Close()

	// Check for MPRESS section
	hasMPRESSSection := false
	for _, section := range peFile.Sections {
		name := section.Name
		// Remove trailing null characters
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		nameStr := string(name)
		if nameStr == ".MPRESS" || nameStr == ".mpress" || nameStr == "MPRESS" ||
			nameStr == ".MPRESS1" || nameStr == ".MPRESS2" {
			hasMPRESSSection = true
			break
		}
	}

	if hasMPRESSSection {
		return MPRESS_VER_1
	}

	// Check for MPRESS signature in file
	f, err := os.Open(path)
	if err != nil {
		return MPRESS_VER_NONE
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		return MPRESS_VER_NONE
	}

	// Read first 64KB to find MPRESS signature
	buf := make([]byte, 64*1024)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return MPRESS_VER_NONE
	}

	// Check for MPRESS signatures
	for i, sig := range mpressSignatures {
		if bytes.Contains(buf[:n], sig) {
			return MPRESS_VER_1 + i
		}
	}

	// Also check near the end of file
	if fileInfo.Size() > 1024 {
		tailBuf := make([]byte, 1024)
		tailN, err := f.ReadAt(tailBuf, fileInfo.Size()-1024)
		if err == nil {
			for i, sig := range mpressSignatures {
				if bytes.Contains(tailBuf[:tailN], sig) {
					return MPRESS_VER_1 + i
				}
			}
		}
	}

	// Check entry point code for MPRESS characteristics
	ep := getEP(path)
	if ep > 0 {
		epbuff := make([]byte, 512)
		_, err = f.ReadAt(epbuff, int64(ep))
		if err == nil {
			// MPRESS often has specific patterns in entry point
			if hasMPRESSPattern(epbuff) {
				return MPRESS_VER_1
			}
		}
	}

	return MPRESS_VER_NONE
}

// hasMPRESSPattern checks for MPRESS-specific patterns in entry point code
func hasMPRESSPattern(epbuff []byte) bool {
	// MPRESS entry point often contains specific instruction sequences
	if len(epbuff) < 10 {
		return false
	}

	// Pattern 1: PUSHAD (0x60) followed by CALL
	if epbuff[0] == 0x60 { // PUSHAD
		// Look for CALL instruction nearby
		for i := 1; i < len(epbuff)-5 && i < 20; i++ {
			if epbuff[i] == 0xE8 { // CALL
				return true
			}
		}
	}

	// Pattern 2: Specific byte sequences common in MPRESS
	mpressPatterns := [][]byte{
		{0x60, 0xE8},           // PUSHAD, CALL
		{0x9C, 0x60},           // PUSHFD, PUSHAD
		{0xE8, 0x00, 0x00, 0x00, 0x00}, // CALL with zero offset
	}

	for _, pattern := range mpressPatterns {
		if bytes.Contains(epbuff, pattern) {
			return true
		}
	}

	return false
}

// Unpack unpacks a MPRESS-packed PE file
func (MPRESS) Unpack(path string) (io.ReaderAt, error) {
	peFile, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}

	fileData := make([]byte, fileInfo.Size())
	_, err = f.ReadAt(fileData, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Find MPRESS signature
	var mpressSigOffset int = -1

	for _, sig := range mpressSignatures {
		idx := bytes.Index(fileData, sig)
		if idx >= 0 {
			mpressSigOffset = idx
			break
		}
	}

	if mpressSigOffset < 0 {
		return nil, io.EOF
	}

	// Get entry point
	ep := getEP(path)
	if ep == 0 {
		return nil, io.EOF
	}

	// Read entry point code
	epbuff := make([]byte, 4096)
	_, err = f.ReadAt(epbuff, int64(ep))
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Find OEP from entry point code
	oepRVA := findMPRESSOEP(epbuff, peFile)
	if oepRVA == 0 {
		// Try alternative method
		oepRVA = searchForOEP(epbuff, peFile)
	}

	if oepRVA == 0 {
		return nil, io.EOF
	}

	// Get PE header offsets
	peHeaderOffset := 0x3C
	peSigOffset := int(binary.LittleEndian.Uint32(fileData[peHeaderOffset:]))

	var entryPointOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPointOffset = peSigOffset + 4 + 20 + 16
	case *pe.OptionalHeader64:
		entryPointOffset = peSigOffset + 4 + 20 + 16
	}

	// Create unpacked file
	unpackedData := make([]byte, len(fileData))
	copy(unpackedData, fileData)

	// Update entry point
	binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)

	// Fix import table
	fixMPRESSImportTable(unpackedData, peFile, peSigOffset)

	// Fix section characteristics
	fixSectionCharacteristics(unpackedData, peFile, peSigOffset)

	return createTempFileFromData(unpackedData)
}

// getEP gets the file offset of PE file entry point
func getEP(path string) uint32 {
	peFile, err := pe.Open(path)
	if err != nil {
		return 0
	}
	defer peFile.Close()

	var entryPoint uint32

	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPoint = optHdr.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryPoint = optHdr.AddressOfEntryPoint
	default:
		return 0
	}

	// Find section containing entry point
	for _, section := range peFile.Sections {
		if section.SectionHeader.VirtualAddress <= entryPoint &&
			entryPoint < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
			offset := section.SectionHeader.Offset + (entryPoint - section.SectionHeader.VirtualAddress)
			return offset
		}
	}

	return 0
}

// findMPRESSOEP finds OEP from MPRESS entry point code
func findMPRESSOEP(epbuff []byte, peFile *pe.File) uint32 {
	// MPRESS stores OEP in various patterns
	// Common pattern: look for CALL or JMP instructions followed by OEP value

	// Search for common patterns
	for i := 0; i < len(epbuff)-8; i++ {
		// Pattern 1: CALL [OEP] or similar
		if epbuff[i] == 0xE8 || epbuff[i] == 0xE9 { // CALL or JMP
			// Check if next 4 bytes form a valid RVA
			if i+5 <= len(epbuff) {
				value := binary.LittleEndian.Uint32(epbuff[i+1:])
				if value >= 0x1000 && value < 0x100000 {
					// Check if in valid section
					for _, section := range peFile.Sections {
						if section.SectionHeader.VirtualAddress <= value &&
							value < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
							return value
						}
					}
				}
			}
		}

		// Pattern 2: PUSH imm32 followed by RET
		if epbuff[i] == 0x68 { // PUSH imm32
			if i+6 <= len(epbuff) && epbuff[i+5] == 0xC3 { // RET
				value := binary.LittleEndian.Uint32(epbuff[i+1:])
				if value >= 0x1000 && value < 0x100000 {
					// Check if in valid section
					for _, section := range peFile.Sections {
						if section.SectionHeader.VirtualAddress <= value &&
							value < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
							return value
						}
					}
				}
			}
		}

		// Pattern 3: Direct value
		if i+4 <= len(epbuff) {
			value := binary.LittleEndian.Uint32(epbuff[i:])
			if value >= 0x1000 && value < 0x100000 {
				// Check if it's in a valid section
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= value &&
						value < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						return value
					}
				}
			}
		}
	}

	return 0
}

// searchForOEP searches for a valid OEP value in entry point code
func searchForOEP(epbuff []byte, peFile *pe.File) uint32 {
	// Search for values that could be valid RVAs in sections
	for i := 0; i < len(epbuff)-4; i += 4 {
		value := binary.LittleEndian.Uint32(epbuff[i:])
		if value >= 0x1000 && value < 0x100000 {
			// Check if this RVA is in a valid section
			for _, section := range peFile.Sections {
				if section.SectionHeader.VirtualAddress <= value &&
					value < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
					return value
				}
			}
		}
	}
	return 0
}

// fixMPRESSImportTable attempts to fix the import table
func fixMPRESSImportTable(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	var dataDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirOffset = peSigOffset + 4 + 20 + 96
	case *pe.OptionalHeader64:
		dataDirOffset = peSigOffset + 4 + 20 + 112
	default:
		return
	}

	// Import table is at index 1
	importTableRVAOffset := dataDirOffset + 8
	importTableSizeOffset := dataDirOffset + 12

	// Try to find import table by searching for common DLL names
	commonDLLs := [][]byte{
		[]byte("kernel32.dll"),
		[]byte("KERNEL32.DLL"),
		[]byte("user32.dll"),
		[]byte("USER32.DLL"),
		[]byte("ntdll.dll"),
		[]byte("NTDLL.DLL"),
	}

	for _, section := range peFile.Sections {
		if section.SectionHeader.Size == 0 {
			continue
		}

		sectionData := make([]byte, section.SectionHeader.Size)
		sectionFileOffset := section.SectionHeader.Offset
		if int(sectionFileOffset)+int(section.SectionHeader.Size) <= len(unpackedData) {
			copy(sectionData, unpackedData[sectionFileOffset:])

			for _, dllName := range commonDLLs {
				idx := bytes.Index(sectionData, dllName)
				if idx >= 0 {
					// Found DLL name, try to find import descriptor
					dllNameRVA := section.SectionHeader.VirtualAddress + uint32(idx)

					// Search backwards for import descriptor
					searchStart := idx
					if searchStart > 0x1000 {
						searchStart -= 0x1000
					} else {
						searchStart = 0
					}

					for i := searchStart; i <= idx && i+20 <= len(sectionData); i += 4 {
						nameRVA := binary.LittleEndian.Uint32(sectionData[i+12:])
						if nameRVA == dllNameRVA {
							// Found potential import descriptor
							importTableRVA := section.SectionHeader.VirtualAddress + uint32(i)
							importTableSize := uint32(20)

							// Calculate size
							for j := i + 20; j+20 <= len(sectionData); j += 20 {
								allZero := true
								for k := 0; k < 20; k++ {
									if sectionData[j+k] != 0 {
										allZero = false
										break
									}
								}
								if allZero {
									importTableSize = uint32(j - i + 20)
									break
								}
								importTableSize += 20
								if importTableSize > 0x2000 {
									break
								}
							}

							binary.LittleEndian.PutUint32(unpackedData[importTableRVAOffset:], importTableRVA)
							binary.LittleEndian.PutUint32(unpackedData[importTableSizeOffset:], importTableSize)
							return
						}
					}
				}
			}
		}
	}
}

// fixSectionCharacteristics fixes section characteristics
func fixSectionCharacteristics(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	var sectionHeaderOffset int
	var numSections uint16

	numSectionsOffset := peSigOffset + 6
	if numSectionsOffset+2 <= len(unpackedData) {
		numSections = binary.LittleEndian.Uint16(unpackedData[numSectionsOffset:])
	}

	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 224
	case *pe.OptionalHeader64:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 240
	default:
		return
	}

	for i := 0; i < int(numSections) && sectionHeaderOffset+40*(i+1) <= len(unpackedData); i++ {
		sectionOffset := sectionHeaderOffset + 40*i
		charOffset := sectionOffset + 36

		if charOffset+4 <= len(unpackedData) {
			currentChar := binary.LittleEndian.Uint32(unpackedData[charOffset:])
			// Remove write protection if needed
			currentChar &^= 0x80000000 // Remove IMAGE_SCN_MEM_WRITE if incorrectly set
			// Ensure readable
			currentChar |= 0x40000000 // IMAGE_SCN_MEM_READ
			binary.LittleEndian.PutUint32(unpackedData[charOffset:], currentChar)
		}
	}
}

// createTempFileFromData creates a temporary file from byte data
func createTempFileFromData(data []byte) (io.ReaderAt, error) {
	tmpFile, err := os.CreateTemp("", "unpack_mpress_*.exe")
	if err != nil {
		return nil, err
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, err
	}
	tmpFile.Close()

	result, err := os.Open(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	return result, nil
}

