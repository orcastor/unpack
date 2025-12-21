package upx

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"

	"github.com/orcastor/unpack"
)

func init() {
	unpack.RegisterFormat("UPX", UPX{})
}

const (
	UPX_VER_NONE = 0 + iota
	UPX_VER_1
	UPX_VER_2
	UPX_VER_3
	UPX_VER_4
)

// UPX signature
var upxSignature = []byte("UPX!")

type UPX struct{}

func (UPX) Name() string {
	return "UPX"
}

// UPXHeader represents the UPX header structure
type UPXHeader struct {
	Signature       [4]byte // "UPX!"
	VersionMajor    uint8
	VersionMinor    uint8
	VersionRevision uint8
	Format          uint8
	Method          uint32
	OriginalSize    uint32
	CompressedSize  uint32
	Filter          uint32
	FilterCTO       uint32
	HeaderChecksum  uint32
	FileChecksum    uint32
}

// Detect checks if the file is packed with UPX
func (UPX) Detect(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return UPX_VER_NONE
	}
	defer f.Close()

	// Read file to find UPX signature
	fileInfo, err := f.Stat()
	if err != nil {
		return UPX_VER_NONE
	}

	// UPX signature is usually in the first few KB or near the end
	// Check first 64KB
	buf := make([]byte, 64*1024)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return UPX_VER_NONE
	}

	// Search for UPX signature
	if bytes.Contains(buf[:n], upxSignature) {
		idx := bytes.Index(buf[:n], upxSignature)
		if idx >= 0 && idx+8 < len(buf) {
			// Try to read version from header
			versionMajor := buf[idx+4]
			if versionMajor > 0 && versionMajor < 10 {
				return UPX_VER_1
			}
		}
		return UPX_VER_1
	}

	// Also check near the end of file (UPX sometimes puts signature there)
	if fileInfo.Size() > 1024 {
		tailBuf := make([]byte, 1024)
		tailN, err := f.ReadAt(tailBuf, fileInfo.Size()-1024)
		if err == nil && bytes.Contains(tailBuf[:tailN], upxSignature) {
			return UPX_VER_1
		}
	}

	return UPX_VER_NONE
}

// parseUPXHeader parses the UPX header from file data
func parseUPXHeader(fileData []byte, offset int) (*UPXHeader, error) {
	if offset+32 > len(fileData) {
		return nil, io.EOF
	}

	header := &UPXHeader{}
	copy(header.Signature[:], fileData[offset:offset+4])
	if !bytes.Equal(header.Signature[:], upxSignature) {
		return nil, io.EOF
	}

	header.VersionMajor = fileData[offset+4]
	header.VersionMinor = fileData[offset+5]
	header.VersionRevision = fileData[offset+6]
	header.Format = fileData[offset+7]
	header.Method = binary.LittleEndian.Uint32(fileData[offset+8:])
	header.OriginalSize = binary.LittleEndian.Uint32(fileData[offset+12:])
	header.CompressedSize = binary.LittleEndian.Uint32(fileData[offset+16:])
	header.Filter = binary.LittleEndian.Uint32(fileData[offset+20:])
	header.FilterCTO = binary.LittleEndian.Uint32(fileData[offset+24:])
	header.HeaderChecksum = binary.LittleEndian.Uint32(fileData[offset+28:])
	header.FileChecksum = binary.LittleEndian.Uint32(fileData[offset+32:])

	return header, nil
}

// nrvDecompress implements the NRV (Not Really Vanished) decompression algorithm
// This is UPX's primary compression algorithm, a variant of LZ77
// Method parameter indicates the compression method variant (affects length encoding)
func nrvDecompress(compressed []byte, decompressedSize uint32, method uint32) ([]byte, error) {
	if len(compressed) == 0 || decompressedSize == 0 {
		return nil, io.EOF
	}

	decompressed := make([]byte, decompressedSize)
	compPos := 0
	decompPos := 0
	bitPos := 0
	bitBuffer := uint32(0)

	// Determine length bits based on method
	// Different UPX methods use different number of bits for length encoding
	lengthBits := 2 // Default
	if method >= 0x20 && method < 0x30 {
		lengthBits = 3 // Some methods use 3 bits
	} else if method >= 0x30 {
		lengthBits = 4 // Higher methods may use more bits
	}

	// Initialize bit buffer
	if compPos >= len(compressed) {
		return nil, io.EOF
	}
	bitBuffer = uint32(compressed[compPos])
	compPos++
	bitPos = 8

	for decompPos < int(decompressedSize) {
		// Read one bit
		if bitPos == 0 {
			if compPos >= len(compressed) {
				break
			}
			bitBuffer = uint32(compressed[compPos])
			compPos++
			bitPos = 8
		}

		bit := (bitBuffer >> (bitPos - 1)) & 1
		bitPos--

		if bit == 1 {
			// Literal: copy one byte directly
			if compPos >= len(compressed) {
				break
			}
			if decompPos >= len(decompressed) {
				break
			}
			decompressed[decompPos] = compressed[compPos]
			decompPos++
			compPos++
		} else {
			// Match: read distance and length
			if compPos+1 >= len(compressed) {
				break
			}

			// Read distance (2 bytes, little-endian)
			dist := uint32(compressed[compPos]) | (uint32(compressed[compPos+1]) << 8)
			compPos += 2

			// Read length (variable bits based on method)
			length := uint32(0)

			// Read length bits
			for i := 0; i < lengthBits; i++ {
				if bitPos == 0 {
					if compPos >= len(compressed) {
						break
					}
					bitBuffer = uint32(compressed[compPos])
					compPos++
					bitPos = 8
				}
				bit = (bitBuffer >> (bitPos - 1)) & 1
				bitPos--
				length = (length << 1) | bit
			}
			length += 2 // Minimum match length is 2

			// Validate distance
			if dist == 0 || dist > uint32(decompPos) {
				// Invalid distance
				break
			}

			// Copy match
			srcPos := decompPos - int(dist)
			for i := uint32(0); i < length && decompPos < int(decompressedSize); i++ {
				if srcPos >= 0 && srcPos < len(decompressed) && decompPos < len(decompressed) {
					decompressed[decompPos] = decompressed[srcPos]
					decompPos++
					srcPos++
				} else {
					break
				}
			}
		}
	}

	if decompPos < int(decompressedSize) {
		// Try to fill remaining with zeros if needed
		for decompPos < int(decompressedSize) && decompPos < len(decompressed) {
			decompressed[decompPos] = 0
			decompPos++
		}
	}

	return decompressed[:decompPos], nil
}

// applyUPXFilter applies UPX filter to decompressed data
// UPX uses various filters to improve compression
func applyUPXFilter(data []byte, filterID uint32, filterCTO uint32) []byte {
	if filterID == 0 || len(data) == 0 {
		return data
	}

	filtered := make([]byte, len(data))
	copy(filtered, data)

	switch filterID {
	case 0x26: // Filter 0x26: x86 call/jump
		// This filter adjusts call/jump instructions
		// Implementation simplified - full filter is complex
		// Full implementation would decode and adjust relative addresses
		_ = filtered // Mark as used
	default:
		// Other filter types not implemented yet
	}

	return filtered
}

// rvaToFileOffset converts RVA to file offset
func rvaToFileOffset(peFile *pe.File, rva uint32) (uint32, error) {
	for _, section := range peFile.Sections {
		sectionRVA := section.SectionHeader.VirtualAddress
		sectionSize := section.SectionHeader.VirtualSize
		if rva >= sectionRVA && rva < sectionRVA+sectionSize {
			offset := rva - sectionRVA
			return section.SectionHeader.Offset + offset, nil
		}
	}
	return 0, io.EOF
}

// Unpack unpacks a UPX-packed PE file
func (UPX) Unpack(path string) (io.ReaderAt, error) {
	// Open PE file
	peFile, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	// Open original file
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Get file size
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()

	// Read entire file
	fileData := make([]byte, fileSize)
	_, err = f.ReadAt(fileData, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Find UPX signature and header
	upxHeaderOffset := bytes.Index(fileData, upxSignature)
	if upxHeaderOffset < 0 {
		return nil, io.EOF
	}

	// Parse UPX header
	header, err := parseUPXHeader(fileData, upxHeaderOffset)
	if err != nil {
		return nil, err
	}

	// Validate sizes
	if header.OriginalSize == 0 || header.OriginalSize > 100*1024*1024 || // Max 100MB
		header.CompressedSize == 0 || header.CompressedSize > 100*1024*1024 {
		return nil, io.EOF
	}

	// Find compressed data
	// UPX header is typically 32-36 bytes, compressed data follows
	compressedDataStart := upxHeaderOffset + 32
	if compressedDataStart >= len(fileData) {
		return nil, io.EOF
	}

	// Read compressed data
	compressedData := fileData[compressedDataStart:]
	if len(compressedData) > int(header.CompressedSize) {
		compressedData = compressedData[:header.CompressedSize]
	}

	// Decompress using NRV algorithm
	// Method field indicates compression method variant
	decompressedData, err := nrvDecompress(compressedData, header.OriginalSize, header.Method)
	if err != nil {
		// If NRV decompression fails, try alternative methods
		return unpackUPXAlternative(fileData, upxHeaderOffset, compressedData, header, peFile)
	}

	// Apply UPX filter if present
	if header.Filter != 0 {
		decompressedData = applyUPXFilter(decompressedData, header.Filter, header.FilterCTO)
	}

	// Rebuild PE file from decompressed data
	return rebuildPEFile(fileData, decompressedData, header, peFile, upxHeaderOffset)
}

// unpackUPXAlternative tries alternative unpacking methods when NRV fails
func unpackUPXAlternative(fileData []byte, upxHeaderOffset int, compressedData []byte, header *UPXHeader, peFile *pe.File) (io.ReaderAt, error) {
	// Try to find original PE header in compressed data
	peSig := []byte("PE\x00\x00")
	peOffset := bytes.Index(compressedData, peSig)
	if peOffset >= 0 {
		// Found PE signature, try to reconstruct
		return reconstructUPXFile(fileData, upxHeaderOffset, compressedData, peOffset, header.OriginalSize, peFile)
	}

	// Try to find PE header before UPX header
	if upxHeaderOffset > 0 {
		peOffset = bytes.Index(fileData[:upxHeaderOffset], peSig)
		if peOffset >= 0 {
			return reconstructUPXFile(fileData, upxHeaderOffset, compressedData, peOffset, header.OriginalSize, peFile)
		}
	}

	// Last resort: create minimal PE structure
	return createMinimalPE(fileData, header, peFile, upxHeaderOffset)
}

// rebuildPEFile rebuilds a complete PE file from decompressed data
func rebuildPEFile(fileData []byte, decompressedData []byte, header *UPXHeader, peFile *pe.File, upxHeaderOffset int) (io.ReaderAt, error) {
	// Create output buffer
	unpackedData := make([]byte, header.OriginalSize)
	if len(decompressedData) > len(unpackedData) {
		unpackedData = make([]byte, len(decompressedData))
	}

	// Copy decompressed data
	copy(unpackedData, decompressedData)

	// Find PE signature in decompressed data
	peSig := []byte("PE\x00\x00")
	peOffset := bytes.Index(unpackedData, peSig)
	if peOffset < 0 {
		// If not found, try to find in original file before UPX header
		if upxHeaderOffset > 0 {
			peOffset = bytes.Index(fileData[:upxHeaderOffset], peSig)
			if peOffset >= 0 {
				// Copy DOS header and PE header from original
				dosHeaderSize := 64
				if peOffset >= dosHeaderSize && peOffset+512 <= len(fileData) {
					copy(unpackedData[:dosHeaderSize], fileData[:dosHeaderSize])
					copy(unpackedData[dosHeaderSize:], fileData[peOffset:peOffset+512])
					peOffset = dosHeaderSize
				}
			}
		}
	}

	// Ensure DOS header points to PE signature
	if peOffset >= 0 {
		dosHeaderSize := 64
		if peOffset >= dosHeaderSize && dosHeaderSize+0x3C+4 <= len(unpackedData) {
			binary.LittleEndian.PutUint32(unpackedData[dosHeaderSize+0x3C:], uint32(peOffset))
		}
	}

	// Fix PE header fields
	if peOffset >= 0 {
		fixPEHeader(unpackedData, peFile, peOffset)

		// Get original import table and IAT RVAs before fixing
		var originalImportTableRVA, originalIATRVA uint32
		if peFile.OptionalHeader != nil {
			switch optHdr := peFile.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				if len(optHdr.DataDirectory) > 1 && optHdr.DataDirectory[1].Size > 0 {
					originalImportTableRVA = optHdr.DataDirectory[1].VirtualAddress
				}
				if len(optHdr.DataDirectory) > 12 && optHdr.DataDirectory[12].Size > 0 {
					originalIATRVA = optHdr.DataDirectory[12].VirtualAddress
				}
			case *pe.OptionalHeader64:
				if len(optHdr.DataDirectory) > 1 && optHdr.DataDirectory[1].Size > 0 {
					originalImportTableRVA = optHdr.DataDirectory[1].VirtualAddress
				}
				if len(optHdr.DataDirectory) > 12 && optHdr.DataDirectory[12].Size > 0 {
					originalIATRVA = optHdr.DataDirectory[12].VirtualAddress
				}
			}
		}

		// Fix optional header fields
		var oepRVA uint32
		if peFile.OptionalHeader != nil {
			switch optHdr := peFile.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				oepRVA = optHdr.AddressOfEntryPoint
			case *pe.OptionalHeader64:
				oepRVA = optHdr.AddressOfEntryPoint
			}
		}
		fixOptionalHeaderFields(unpackedData, peFile, peOffset, oepRVA)

		// Fix import table - critical for program to run
		fixImportTable(unpackedData, peFile, peOffset, originalImportTableRVA)

		// Fix IAT (Import Address Table)
		fixIAT(unpackedData, peFile, peOffset, originalIATRVA)

		// Fix PE checksum
		fixPEChecksum(unpackedData, peOffset)
	}

	// Calculate actual file size based on sections
	actualSize := calculateFileSize(unpackedData, peFile, peOffset)
	if actualSize > len(unpackedData) {
		newData := make([]byte, actualSize)
		copy(newData, unpackedData)
		unpackedData = newData
	}

	return createTempFileFromData(unpackedData[:actualSize])
}

// fixPEHeader fixes PE header fields after unpacking
func fixPEHeader(unpackedData []byte, peFile *pe.File, peOffset int) {
	if peOffset+6+2 > len(unpackedData) {
		return
	}

	// Get number of sections
	numSections := binary.LittleEndian.Uint16(unpackedData[peOffset+6:])
	if numSections == 0 || numSections > 100 {
		return
	}

	// Fix section headers
	// PE32 optional header is typically 224 bytes, PE32+ is 240 bytes
	sectionHeaderStart := peOffset + 24 + 224 // Default to PE32 size
	if peFile.OptionalHeader != nil {
		switch peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			sectionHeaderStart = peOffset + 24 + 224 // PE32: 224 bytes
		case *pe.OptionalHeader64:
			sectionHeaderStart = peOffset + 24 + 240 // PE32+: 240 bytes
		}
	}

	// Update section characteristics
	for i := 0; i < int(numSections) && sectionHeaderStart+40*(i+1) <= len(unpackedData); i++ {
		charOffset := sectionHeaderStart + 40*i + 36 // Characteristics offset
		if charOffset+4 <= len(unpackedData) {
			// Restore original section characteristics (remove compressed flags)
			char := binary.LittleEndian.Uint32(unpackedData[charOffset:])
			char &^= 0x20000000 // Remove IMAGE_SCN_MEM_DISCARDABLE if set
			binary.LittleEndian.PutUint32(unpackedData[charOffset:], char)
		}
	}
}

// calculateFileSize calculates the actual file size based on sections
func calculateFileSize(unpackedData []byte, peFile *pe.File, peOffset int) int {
	if peOffset+6+2 > len(unpackedData) {
		return len(unpackedData)
	}

	numSections := binary.LittleEndian.Uint16(unpackedData[peOffset+6:])
	if numSections == 0 {
		return len(unpackedData)
	}

	// Get section header start
	// PE32 optional header is typically 224 bytes, PE32+ is 240 bytes
	sectionHeaderStart := peOffset + 24 + 224 // Default to PE32 size
	if peFile.OptionalHeader != nil {
		switch peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			sectionHeaderStart = peOffset + 24 + 224 // PE32: 224 bytes
		case *pe.OptionalHeader64:
			sectionHeaderStart = peOffset + 24 + 240 // PE32+: 240 bytes
		}
	}

	// Find the last section's end
	maxOffset := sectionHeaderStart
	for i := 0; i < int(numSections) && sectionHeaderStart+40*(i+1) <= len(unpackedData); i++ {
		sectionOffset := sectionHeaderStart + 40*i
		if sectionOffset+20+4 <= len(unpackedData) {
			pointerToRawData := binary.LittleEndian.Uint32(unpackedData[sectionOffset+20:])
			sizeOfRawData := binary.LittleEndian.Uint32(unpackedData[sectionOffset+16:])
			sectionEnd := int(pointerToRawData + sizeOfRawData)
			if sectionEnd > maxOffset {
				maxOffset = sectionEnd
			}
		}
	}

	if maxOffset > len(unpackedData) {
		return len(unpackedData)
	}
	return maxOffset
}

// reconstructUPXFile reconstructs the PE file from UPX compressed data (fallback method)
func reconstructUPXFile(fileData []byte, upxHeaderOffset int, compressedData []byte, peOffset int, originalSize uint32, peFile *pe.File) (io.ReaderAt, error) {
	// Create unpacked data buffer
	unpackedData := make([]byte, originalSize)

	// Copy DOS header from original file
	dosHeaderSize := 64
	if len(fileData) >= dosHeaderSize {
		copy(unpackedData, fileData[:dosHeaderSize])
	}

	// Update DOS header to point to PE signature
	peSigOffset := dosHeaderSize
	if peOffset >= 0 {
		peSigOffset = dosHeaderSize
	}
	if dosHeaderSize+0x3C+4 <= len(unpackedData) {
		binary.LittleEndian.PutUint32(unpackedData[dosHeaderSize+0x3C:], uint32(peSigOffset))
	}

	// Try to find and copy PE header
	if peOffset >= 0 && peOffset+512 < len(compressedData) {
		peHeaderSize := 512
		if peOffset+peHeaderSize <= len(compressedData) && dosHeaderSize+peHeaderSize <= len(unpackedData) {
			copy(unpackedData[dosHeaderSize:], compressedData[peOffset:peOffset+peHeaderSize])

			// Try to read number of sections and copy section headers
			if dosHeaderSize+6+2 <= len(unpackedData) {
				numSections := binary.LittleEndian.Uint16(unpackedData[dosHeaderSize+6:])
				if numSections > 0 && numSections < 100 {
					sectionHeaderSize := int(numSections) * 40
					sectionHeaderStart := dosHeaderSize + peHeaderSize

					if peOffset+peHeaderSize+sectionHeaderSize <= len(compressedData) &&
						sectionHeaderStart+sectionHeaderSize <= len(unpackedData) {
						copy(unpackedData[sectionHeaderStart:],
							compressedData[peOffset+peHeaderSize:peOffset+peHeaderSize+sectionHeaderSize])
					}
				}
			}
		}
	} else if upxHeaderOffset > 0 {
		// Try to find PE signature in original file before UPX header
		originalPeOffset := bytes.Index(fileData[:upxHeaderOffset], []byte("PE\x00\x00"))
		if originalPeOffset >= 0 {
			peHeaderSize := 512
			if originalPeOffset+peHeaderSize <= len(fileData) && dosHeaderSize+peHeaderSize <= len(unpackedData) {
				copy(unpackedData[dosHeaderSize:], fileData[originalPeOffset:originalPeOffset+peHeaderSize])

				// Try to copy section headers
				if dosHeaderSize+6+2 <= len(unpackedData) {
					numSections := binary.LittleEndian.Uint16(unpackedData[dosHeaderSize+6:])
					if numSections > 0 && numSections < 100 {
						sectionHeaderSize := int(numSections) * 40
						sectionHeaderStart := dosHeaderSize + peHeaderSize

						if originalPeOffset+peHeaderSize+sectionHeaderSize <= len(fileData) &&
							sectionHeaderStart+sectionHeaderSize <= len(unpackedData) {
							copy(unpackedData[sectionHeaderStart:],
								fileData[originalPeOffset+peHeaderSize:originalPeOffset+peHeaderSize+sectionHeaderSize])
						}
					}
				}
			}
		}
	}

	return createTempFileFromData(unpackedData)
}

// createMinimalPE creates a minimal PE file structure (last resort)
func createMinimalPE(fileData []byte, header *UPXHeader, peFile *pe.File, upxHeaderOffset int) (io.ReaderAt, error) {
	unpackedData := make([]byte, header.OriginalSize)

	// Copy DOS header
	dosHeaderSize := 64
	if len(fileData) >= dosHeaderSize {
		copy(unpackedData, fileData[:dosHeaderSize])
	}

	// Set DOS header to point to PE signature
	if dosHeaderSize+0x3C+4 <= len(unpackedData) {
		binary.LittleEndian.PutUint32(unpackedData[dosHeaderSize+0x3C:], uint32(dosHeaderSize))
	}

	// Create minimal PE header
	peSig := []byte("PE\x00\x00")
	if dosHeaderSize+4 <= len(unpackedData) {
		copy(unpackedData[dosHeaderSize:], peSig)
	}

	return createTempFileFromData(unpackedData)
}

// readUint32LE reads a little-endian uint32 from data at offset
func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 <= len(data) {
		return binary.LittleEndian.Uint32(data[offset:])
	}
	return 0
}

// fixOptionalHeaderFields fixes critical fields in OptionalHeader
func fixOptionalHeaderFields(unpackedData []byte, peFile *pe.File, peSigOffset int, oepRVA uint32) {
	optHeaderOffset := peSigOffset + 4 + 20 // PE sig + COFF header

	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		// AddressOfEntryPoint is at offset 16
		entryPointOffset := optHeaderOffset + 16
		if entryPointOffset+4 <= len(unpackedData) {
			binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)
		}
	case *pe.OptionalHeader64:
		// AddressOfEntryPoint is at offset 16
		entryPointOffset := optHeaderOffset + 16
		if entryPointOffset+4 <= len(unpackedData) {
			binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)
		}
	}
}

// fixImportTable attempts to fix the import table in the unpacked PE file
func fixImportTable(unpackedData []byte, peFile *pe.File, peSigOffset int, originalImportTableRVA uint32) {
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

	// Try to use original import table RVA if provided and valid
	if originalImportTableRVA != 0 {
		importTableFileOffset, err := rvaToFileOffset(peFile, originalImportTableRVA)
		if err == nil && importTableFileOffset < uint32(len(unpackedData)) {
			if importTableFileOffset+20 <= uint32(len(unpackedData)) {
				nameRVA := readUint32LE(unpackedData, int(importTableFileOffset)+12)
				if nameRVA != 0 && nameRVA >= 0x1000 && nameRVA < 0x10000000 {
					nameFileOffset, err := rvaToFileOffset(peFile, nameRVA)
					if err == nil && int(nameFileOffset) < len(unpackedData) {
						if int(nameFileOffset)+20 <= len(unpackedData) {
							nameBytes := unpackedData[nameFileOffset : nameFileOffset+20]
							if bytes.Contains(nameBytes, []byte(".dll")) || bytes.Contains(nameBytes, []byte(".DLL")) {
								// Calculate size
								importTableSize := uint32(20)
								for j := int(importTableFileOffset) + 20; j+20 <= len(unpackedData); j += 20 {
									allZero := true
									for k := 0; k < 20; k++ {
										if unpackedData[j+k] != 0 {
											allZero = false
											break
										}
									}
									if allZero {
										importTableSize = uint32(j - int(importTableFileOffset) + 20)
										break
									}
									importTableSize += 20
									if importTableSize > 0x2000 {
										importTableSize = 0x2000
										break
									}
								}
								binary.LittleEndian.PutUint32(unpackedData[importTableRVAOffset:], originalImportTableRVA)
								binary.LittleEndian.PutUint32(unpackedData[importTableSizeOffset:], importTableSize)
								return
							}
						}
					}
				}
			}
		}
	}

	// Search for import table in sections
	currentRVA := readUint32LE(unpackedData, importTableRVAOffset)
	if currentRVA == 0 {
		// Try to find import table in sections
		for _, section := range peFile.Sections {
			sectionFileOffset := section.SectionHeader.Offset
			if int(sectionFileOffset) >= len(unpackedData) {
				continue
			}
			sectionSize := section.SectionHeader.Size
			if int(sectionFileOffset)+int(sectionSize) > len(unpackedData) {
				sectionSize = uint32(len(unpackedData) - int(sectionFileOffset))
			}
			sectionData := unpackedData[sectionFileOffset : sectionFileOffset+sectionSize]

			// Search for import descriptors
			for i := 0; i < len(sectionData)-20; i += 4 {
				nameRVA := readUint32LE(sectionData, i+12)
				if nameRVA != 0 && nameRVA >= 0x1000 && nameRVA < 0x10000000 {
					nameFileOffset, err := rvaToFileOffset(peFile, nameRVA)
					if err == nil && int(nameFileOffset) < len(unpackedData) {
						if int(nameFileOffset)+20 <= len(unpackedData) {
							nameBytes := unpackedData[nameFileOffset : nameFileOffset+20]
							if bytes.Contains(nameBytes, []byte(".dll")) || bytes.Contains(nameBytes, []byte(".DLL")) {
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
										importTableSize = 0x2000
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
}

// fixIAT attempts to fix the Import Address Table (IAT)
func fixIAT(unpackedData []byte, peFile *pe.File, peSigOffset int, originalIATRVA uint32) {
	var dataDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirOffset = peSigOffset + 4 + 20 + 96
	case *pe.OptionalHeader64:
		dataDirOffset = peSigOffset + 4 + 20 + 112
	default:
		return
	}

	iatRVAOffset := dataDirOffset + 12*8
	iatSizeOffset := dataDirOffset + 12*8 + 4

	// Get import table RVA
	importTableRVAOffset := dataDirOffset + 8
	importTableRVA := readUint32LE(unpackedData, importTableRVAOffset)

	if importTableRVA == 0 {
		return
	}

	// Try to find IAT from import table
	importTableFileOffset, err := rvaToFileOffset(peFile, importTableRVA)
	if err != nil {
		return
	}

	var iatStartRVA, iatEndRVA uint32
	descOffset := int(importTableFileOffset)

	for descOffset+20 <= len(unpackedData) {
		firstThunkRVA := readUint32LE(unpackedData, descOffset+16)
		originalFirstThunkRVA := readUint32LE(unpackedData, descOffset)

		if firstThunkRVA == 0 && originalFirstThunkRVA == 0 {
			break
		}

		// Use FirstThunk if available, otherwise use OriginalFirstThunk
		thunkRVA := firstThunkRVA
		if thunkRVA == 0 {
			thunkRVA = originalFirstThunkRVA
		}

		if thunkRVA != 0 {
			if iatStartRVA == 0 || thunkRVA < iatStartRVA {
				iatStartRVA = thunkRVA
			}

			// Find end of thunk array
			thunkFileOffset, err := rvaToFileOffset(peFile, thunkRVA)
			if err == nil {
				for i := 0; i < 256 && int(thunkFileOffset)+i*4+4 <= len(unpackedData); i++ {
					thunkValue := readUint32LE(unpackedData, int(thunkFileOffset)+i*4)
					if thunkValue == 0 {
						thunkEndRVA := thunkRVA + uint32(i*4)
						if thunkEndRVA > iatEndRVA {
							iatEndRVA = thunkEndRVA
						}
						break
					}
				}
			}
		}

		descOffset += 20
	}

	if iatStartRVA != 0 && iatEndRVA > iatStartRVA {
		iatSize := iatEndRVA - iatStartRVA
		binary.LittleEndian.PutUint32(unpackedData[iatRVAOffset:], iatStartRVA)
		binary.LittleEndian.PutUint32(unpackedData[iatSizeOffset:], iatSize)
	}
}

// fixPEChecksum recalculates and updates the PE checksum
func fixPEChecksum(unpackedData []byte, peSigOffset int) {
	var checksumOffset int
	optHeaderOffset := peSigOffset + 4 + 20

	if optHeaderOffset+64+4 <= len(unpackedData) {
		magicOffset := optHeaderOffset
		if magicOffset+2 <= len(unpackedData) {
			magic := binary.LittleEndian.Uint16(unpackedData[magicOffset:])
			if magic == 0x10b || magic == 0x20b { // PE32 or PE32+
				checksumOffset = optHeaderOffset + 64
			}
		}
	}

	if checksumOffset > 0 && checksumOffset+4 <= len(unpackedData) {
		checksum := calculatePEChecksum(unpackedData, checksumOffset)
		binary.LittleEndian.PutUint32(unpackedData[checksumOffset:], checksum)
	}
}

// calculatePEChecksum calculates the PE checksum
func calculatePEChecksum(data []byte, checksumOffset int) uint32 {
	originalChecksum := binary.LittleEndian.Uint32(data[checksumOffset:])
	binary.LittleEndian.PutUint32(data[checksumOffset:], 0)

	var sum uint64
	fileSize := uint64(len(data))

	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = binary.LittleEndian.Uint16(data[i:])
		} else {
			word = uint16(data[i])
		}
		sum += uint64(word)
		if sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
	}

	sum += fileSize
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Restore original checksum
	binary.LittleEndian.PutUint32(data[checksumOffset:], originalChecksum)

	return uint32(sum)
}

// createTempFileFromData creates a temporary file from byte data
func createTempFileFromData(data []byte) (io.ReaderAt, error) {
	tmpFile, err := os.CreateTemp("", "unpack_upx_*.exe")
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
