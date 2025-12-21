package winupack

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"

	"github.com/orcastor/unpack"
)

func init() {
	unpack.RegisterFormat("WinUpack", WinUpack{})
}

const (
	WINUPACK_VER_NONE = 0 + iota
	WINUPACK_VER_1
	WINUPACK_VER_2
)

// WinUpack signatures
var winupackSignatures = [][]byte{
	[]byte("UPX0"),
	[]byte("UPX1"),
	[]byte("UPX!"),
}

type WinUpack struct{}

func (WinUpack) Name() string {
	return "WinUpack"
}

// Detect checks if the file is packed with WinUpack
func (WinUpack) Detect(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return WINUPACK_VER_NONE
	}
	defer f.Close()

	// Read first 64KB
	buf := make([]byte, 64*1024)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return WINUPACK_VER_NONE
	}

	// WinUpack uses UPX-like signatures but with different structure
	// Check for UPX0/UPX1 sections (WinUpack uses similar section names)
	for i, sig := range winupackSignatures {
		if bytes.Contains(buf[:n], sig) {
			// Additional check: WinUpack has specific characteristics
			// Check if there's a .upx0 or .upx1 section
			return WINUPACK_VER_1 + i
		}
	}

	// Also check for WinUpack-specific section names
	if bytes.Contains(buf[:n], []byte(".upx0")) || bytes.Contains(buf[:n], []byte(".upx1")) {
		return WINUPACK_VER_1
	}

	return WINUPACK_VER_NONE
}

// Unpack unpacks a WinUpack-packed PE file
func (WinUpack) Unpack(path string) (io.ReaderAt, error) {
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

	// Check for UPX sections
	hasUPX0 := false
	hasUPX1 := false

	for _, section := range peFile.Sections {
		name := section.Name
		// Remove trailing nulls
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		nameStr := string(name)
		if nameStr == ".upx0" || nameStr == "UPX0" {
			hasUPX0 = true
		}
		if nameStr == ".upx1" || nameStr == "UPX1" {
			hasUPX1 = true
		}
	}

	if !hasUPX0 || !hasUPX1 {
		return nil, io.EOF
	}

	// Get entry point
	ep := getEP(path)
	if ep == 0 {
		return nil, io.EOF
	}

	// Read entry point code to find OEP
	epbuff := make([]byte, 4096)
	_, err = f.ReadAt(epbuff, int64(ep))
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Get entry point RVA for relative address calculation
	var entryPointRVA uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPointRVA = optHdr.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryPointRVA = optHdr.AddressOfEntryPoint
	default:
		return nil, io.EOF
	}

	// Find OEP
	oepRVA := findWinUpackOEP(epbuff, peFile, entryPointRVA)
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
	fixWinUpackImportTable(unpackedData, peFile, peSigOffset)

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

// findWinUpackOEP finds OEP from WinUpack entry point code
func findWinUpackOEP(epbuff []byte, peFile *pe.File, entryPointRVA uint32) uint32 {
	// WinUpack stores OEP in entry point code
	// Common patterns:
	// 1. CALL instruction with OEP
	// 2. JMP instruction with OEP
	// 3. Direct value in code

	for i := 0; i < len(epbuff)-8; i++ {
		// Pattern 1: CALL/JMP with relative offset
		if epbuff[i] == 0xE8 || epbuff[i] == 0xE9 {
			if i+5 <= len(epbuff) {
				// Relative offset (signed 32-bit)
				offset := int32(binary.LittleEndian.Uint32(epbuff[i+1:]))
				// Calculate absolute address: current instruction address + offset + instruction size
				// Current instruction is at entryPointRVA + i
				// Next instruction is at entryPointRVA + i + 5 (CALL/JMP is 5 bytes)
				// Target address = next instruction address + offset
				nextInstructionRVA := entryPointRVA + uint32(i) + 5
				targetRVA := uint32(int32(nextInstructionRVA) + offset)
				
				// Validate the calculated RVA
				if targetRVA >= 0x1000 && targetRVA < 0x100000 {
					// Check if in valid section
					for _, section := range peFile.Sections {
						if section.SectionHeader.VirtualAddress <= targetRVA &&
							targetRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
							return targetRVA
						}
					}
				}
			}
		}

		// Pattern 2: Direct value (PUSH imm32)
		if epbuff[i] == 0x68 {
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

		// Pattern 3: Search for valid RVA
		if i+4 <= len(epbuff) {
			value := binary.LittleEndian.Uint32(epbuff[i:])
			if value >= 0x1000 && value < 0x100000 {
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

// fixWinUpackImportTable attempts to fix the import table
func fixWinUpackImportTable(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	var dataDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirOffset = peSigOffset + 4 + 20 + 96
	case *pe.OptionalHeader64:
		dataDirOffset = peSigOffset + 4 + 20 + 112
	default:
		return
	}

	importTableRVAOffset := dataDirOffset + 8
	importTableSizeOffset := dataDirOffset + 12

	// Try to find import table
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
					dllNameRVA := section.SectionHeader.VirtualAddress + uint32(idx)

					searchStart := idx
					if searchStart > 0x1000 {
						searchStart -= 0x1000
					} else {
						searchStart = 0
					}

					for i := searchStart; i <= idx && i+20 <= len(sectionData); i += 4 {
						nameRVA := binary.LittleEndian.Uint32(sectionData[i+12:])
						if nameRVA == dllNameRVA {
							importTableRVA := section.SectionHeader.VirtualAddress + uint32(i)
							importTableSize := uint32(20)

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
			// Fix characteristics
			currentChar &^= 0x80000000
			currentChar |= 0x40000000 // IMAGE_SCN_MEM_READ
			binary.LittleEndian.PutUint32(unpackedData[charOffset:], currentChar)
		}
	}
}

// createTempFileFromData creates a temporary file from byte data
func createTempFileFromData(data []byte) (io.ReaderAt, error) {
	tmpFile, err := os.CreateTemp("", "unpack_winupack_*.exe")
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
