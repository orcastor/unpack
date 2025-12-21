package fsg

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"

	"github.com/orcastor/unpack"
)

func init() {
	unpack.RegisterFormat("FSG", FSG{})
}

const (
	FSG_VER_NONE = 0 + iota
	FSG_VER_1
	FSG_VER_2
)

// FSG signatures
var fsgSignatures = [][]byte{
	[]byte("FSG!"),
	[]byte("FSG2"),
}

type FSG struct{}

func (FSG) Name() string {
	return "FSG"
}

// Detect checks if the file is packed with FSG
func (FSG) Detect(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return FSG_VER_NONE
	}
	defer f.Close()

	// Read first 64KB to find FSG signature
	buf := make([]byte, 64*1024)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return FSG_VER_NONE
	}

	// Check for FSG signatures
	for i, sig := range fsgSignatures {
		if bytes.Contains(buf[:n], sig) {
			return FSG_VER_1 + i
		}
	}

	return FSG_VER_NONE
}

// Unpack unpacks a FSG-packed PE file
func (FSG) Unpack(path string) (io.ReaderAt, error) {
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

	// Find FSG signature
	var fsgSigOffset int = -1
	var fsgVersion int = FSG_VER_NONE

	for i, sig := range fsgSignatures {
		idx := bytes.Index(fileData, sig)
		if idx >= 0 {
			fsgSigOffset = idx
			fsgVersion = FSG_VER_1 + i
			break
		}
	}

	if fsgSigOffset < 0 {
		return nil, io.EOF
	}

	// FSG stores original entry point and import table information
	// The structure varies by version, but generally:
	// - Original OEP is stored near the signature
	// - Import table information is stored separately

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

	// FSG typically stores OEP in a specific pattern
	// Look for common FSG patterns in entry point code
	oepRVA := findFSGOEP(epbuff, fsgVersion)
	if oepRVA == 0 {
		// Try alternative method: search for valid RVA in entry point code
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
	fixFSGImportTable(unpackedData, peFile, peSigOffset)

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

// findFSGOEP finds OEP from FSG entry point code
func findFSGOEP(epbuff []byte, version int) uint32 {
	// FSG stores OEP in various patterns
	// Common pattern: look for CALL or JMP instructions followed by OEP value

	// Search for common patterns
	for i := 0; i < len(epbuff)-8; i++ {
		// Pattern 1: CALL [OEP] or similar
		if epbuff[i] == 0xE8 || epbuff[i] == 0xE9 { // CALL or JMP
			// Check if next 4 bytes form a valid RVA
			if i+5 <= len(epbuff) {
				value := binary.LittleEndian.Uint32(epbuff[i+1:])
				if value >= 0x1000 && value < 0x100000 {
					return value
				}
			}
		}

		// Pattern 2: Direct value
		if i+4 <= len(epbuff) {
			value := binary.LittleEndian.Uint32(epbuff[i:])
			if value >= 0x1000 && value < 0x100000 {
				// Check if it's not just random data
				// Look for it appearing in a meaningful context
				return value
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

// fixFSGImportTable attempts to fix the import table
func fixFSGImportTable(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	// FSG often stores import table information
	// Try to find and restore it

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
	tmpFile, err := os.CreateTemp("", "unpack_fsg_*.exe")
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

