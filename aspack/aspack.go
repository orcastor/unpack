package aspack

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"

	"github.com/orcastor/unpack"
)

func init() {
	unpack.RegisterFormat("ASPack", ASPack{})
}

const (
	ASPACK_EP_OFFSET_212   = (58 + 0x70e)
	ASPACK_EP_OFFSET_OTHER = (58 + 0x76a)
	ASPACK_EP_OFFSET_242   = (58 + 0x776)

	ASPACK_EPBUFF_OFFSET_21    = (0x4fd)
	ASPACK_EPBUFF_OFFSET_212   = (0x3b9)
	ASPACK_EPBUFF_OFFSET_OTHER = (0x41f)
	ASPACK_EPBUFF_OFFSET_242   = (0x42B)

	ASPACK_BLOCKS_OFFSET_212   = 0x57c
	ASPACK_BLOCKS_OFFSET_OTHER = 0x5d8
	ASPACK_BLOCKS_OFFSET_242   = 0x5e4

	ASPACK_STR_INIT_MLT_OFFSET_212   = 0x70e
	ASPACK_STR_INIT_MLT_OFFSET_OTHER = 0x76a
	ASPACK_STR_INIT_MLT_OFFSET_242   = 0x776

	ASPACK_COMP_BLOCK_OFFSET_212   = 0x6d6
	ASPACK_COMP_BLOCK_OFFSET_OTHER = 0x732
	ASPACK_COMP_BLOCK_OFFSET_242   = 0x73e

	ASPACK_WRKBUF_OFFSET_212   = 0x148
	ASPACK_WRKBUF_OFFSET_OTHER = 0x13a
	ASPACK_WRKBUF_OFFSET_242   = 0x148
)

const (
	ASPACK_VER_NONE = 0 + iota
	ASPACK_VER_21
	ASPACK_VER_212
	ASPACK_VER_OTHER
	ASPACK_VER_242
)

func align(value, alignment uint32) uint32 {
	if alignment == 0 {
		return value
	}
	return (value + alignment - 1) & ^(alignment - 1)
}

// hasASPackSection checks if PE file has .aspack section
func hasASPackSection(path string) bool {
	peFile, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer peFile.Close()

	for _, section := range peFile.Sections {
		name := section.Name
		// Remove trailing null characters
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		if string(name) == ".aspack" {
			return true
		}
	}
	return false
}

// getEP gets the file offset of PE file entry point
func getEP(path string) uint32 {
	// Parse PE file
	peFile, err := pe.Open(path)
	if err != nil {
		return 0
	}
	defer peFile.Close()

	// Get PE header size (assumed from OptionalHeader)
	var hdrSize uint32
	// Get entry point address (RVA)
	var entryPoint uint32
	// Get alignment parameters
	var sectionAlignment, fileAlignment uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		hdrSize = optHdr.SizeOfHeaders
		entryPoint = optHdr.AddressOfEntryPoint
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	case *pe.OptionalHeader64:
		hdrSize = optHdr.SizeOfHeaders
		entryPoint = optHdr.AddressOfEntryPoint
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	default:
		return 0
	}

	// Handle case where RVA is less than PE header size
	if entryPoint < hdrSize {
		return entryPoint
	}

	// Iterate through PE file sections, find section containing entry point, and calculate file offset
	for _, section := range peFile.Sections {
		rvaAligned := align(section.SectionHeader.VirtualAddress, sectionAlignment)
		offsetAligned := align(section.SectionHeader.Offset, fileAlignment)
		vszAligned := align(section.SectionHeader.VirtualSize, sectionAlignment)
		if vszAligned > 0 && rvaAligned <= entryPoint && entryPoint < (rvaAligned+vszAligned) {
			offset := (entryPoint - rvaAligned) + offsetAligned
			return offset
		}
	}

	return 0
}

type ASPack struct{}

func (ASPack) Name() string {
	return "ASPack"
}

func (ASPack) Detect(path string) int {
	// First check if there is .aspack section
	if !hasASPackSection(path) {
		return ASPACK_VER_NONE
	}

	ep := getEP(path)
	if ep == 0 {
		return ASPACK_VER_NONE
	}

	f, err := os.Open(path)
	if err != nil {
		return ASPACK_VER_NONE
	}
	defer f.Close()

	// Read code near entry point
	epbuff := make([]byte, 4096)
	n, err := f.ReadAt(epbuff, int64(ep))
	if err != nil && err != io.EOF {
		return ASPACK_VER_NONE
	}
	if n < 0x500 {
		return ASPACK_VER_NONE
	}

	// Check entry point signature: PUSH 0; RET (0x68 0x00 0x00 0x00 0x00 0xC3)
	signature := []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}

	// Find matching version (check offsets from large to small to avoid misjudgment)
	offsets := []struct {
		offset  int
		version int
	}{
		{ASPACK_EPBUFF_OFFSET_242, ASPACK_VER_242},
		{ASPACK_EPBUFF_OFFSET_OTHER, ASPACK_VER_OTHER},
		{ASPACK_EPBUFF_OFFSET_212, ASPACK_VER_212},
		{ASPACK_EPBUFF_OFFSET_21, ASPACK_VER_21},
	}

	for _, off := range offsets {
		if off.offset+6 <= len(epbuff) {
			if bytes.Equal(epbuff[off.offset:off.offset+6], signature) {
				return off.version
			}
		}
	}

	return ASPACK_VER_NONE
}

// getVersionOffsets gets corresponding offsets based on version
func getVersionOffsets(version int) (epOffset, blocksOffset, compBlockOffset, wrkbufOffset int) {
	switch version {
	case ASPACK_VER_212:
		return ASPACK_EP_OFFSET_212, ASPACK_BLOCKS_OFFSET_212, ASPACK_COMP_BLOCK_OFFSET_212, ASPACK_WRKBUF_OFFSET_212
	case ASPACK_VER_242:
		return ASPACK_EP_OFFSET_242, ASPACK_BLOCKS_OFFSET_242, ASPACK_COMP_BLOCK_OFFSET_242, ASPACK_WRKBUF_OFFSET_242
	case ASPACK_VER_OTHER:
		return ASPACK_EP_OFFSET_OTHER, ASPACK_BLOCKS_OFFSET_OTHER, ASPACK_COMP_BLOCK_OFFSET_OTHER, ASPACK_WRKBUF_OFFSET_OTHER
	case ASPACK_VER_21:
		// Version 2.1 uses different offsets - need to find them dynamically
		// For now, use approximate offsets based on common patterns
		return 0, 0x500, 0x600, 0x200
	default:
		return 0, 0, 0, 0
	}
}

// CompressedBlock represents a compressed data block
type CompressedBlock struct {
	SourceRVA        uint32 // Source RVA in compressed data
	DestRVA          uint32 // Destination RVA in decompressed data
	CompressedSize   uint32 // Compressed size
	DecompressedSize uint32 // Decompressed size
}

// readOEPFromEPBuff reads OEP (Original Entry Point) from entry point buffer
func readOEPFromEPBuff(epbuff []byte, version int, epFileOffset uint32) (uint32, error) {
	var oepOffset int
	switch version {
	case ASPACK_VER_212:
		oepOffset = ASPACK_EP_OFFSET_212
	case ASPACK_VER_242:
		oepOffset = ASPACK_EP_OFFSET_242
	case ASPACK_VER_OTHER:
		oepOffset = ASPACK_EP_OFFSET_OTHER
	case ASPACK_VER_21:
		// Version 2.1: OEP location can vary
		// First, try to find OEP before the PUSH 0; RET pattern
		// Common locations: 9 bytes before (0x4F4) or in the PUSH instruction itself
		if len(epbuff) < ASPACK_EPBUFF_OFFSET_21+6 {
			return 0, io.EOF
		}

		// Check if PUSH 0; RET pattern exists at expected offset
		if epbuff[ASPACK_EPBUFF_OFFSET_21] == 0x68 &&
			epbuff[ASPACK_EPBUFF_OFFSET_21+1] == 0x00 &&
			epbuff[ASPACK_EPBUFF_OFFSET_21+5] == 0xC3 {
			// Try reading OEP from 9 bytes before PUSH 0; RET (common location)
			if ASPACK_EPBUFF_OFFSET_21 >= 9 && len(epbuff) >= ASPACK_EPBUFF_OFFSET_21-9+4 {
				oepRVA := readUint32LE(epbuff, ASPACK_EPBUFF_OFFSET_21-9)
				// Validate OEP is in reasonable range
				if oepRVA >= 0x1000 && oepRVA < 0x10000000 {
					return oepRVA, nil
				}
			}

			// Fallback: try reading from PUSH instruction (though it's usually 0)
			oepRVA := readUint32LE(epbuff, ASPACK_EPBUFF_OFFSET_21+1)
			if oepRVA >= 0x1000 && oepRVA < 0x10000000 {
				return oepRVA, nil
			}

			// If both failed, search for a valid OEP value near the signature
			// Search in a range around the PUSH 0; RET pattern
			for offset := ASPACK_EPBUFF_OFFSET_21 - 0x20; offset < ASPACK_EPBUFF_OFFSET_21; offset += 4 {
				if offset >= 0 && offset+4 <= len(epbuff) {
					oepRVA := readUint32LE(epbuff, offset)
					if oepRVA >= 0x1000 && oepRVA < 0x100000 {
						return oepRVA, nil
					}
				}
			}
		}

		return 0, io.EOF
	default:
		return 0, io.EOF
	}

	if len(epbuff) < oepOffset+4 {
		return 0, io.EOF
	}

	// Read OEP RVA from the offset
	oepRVA := readUint32LE(epbuff, oepOffset)
	return oepRVA, nil
}

// readUint32LE reads little-endian uint32 from byte array
func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}

// aspackDecompress is the ASPack decompression algorithm
func aspackDecompress(compressed []byte, decompressedSize uint32) ([]byte, error) {
	if len(compressed) == 0 || decompressedSize == 0 {
		return nil, io.EOF
	}

	decompressed := make([]byte, decompressedSize)
	compPos := 0
	decompPos := 0
	bitPos := 0
	bitBuffer := uint32(0)

	// Read initial bits
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
			// Directly copy one byte
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
			// Read distance and length
			if compPos+1 >= len(compressed) {
				break
			}

			// Read distance (2 bytes, little-endian, as signed int16)
			// In ASPack, distance is signed, where negative values are used for encoding
			distRaw := int16(compressed[compPos]) | (int16(compressed[compPos+1]) << 8)
			dist := uint32(-distRaw) // Convert to positive distance
			compPos += 2

			// Read length (2 bits)
			length := uint32(0)
			for i := 0; i < 2; i++ {
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
			length += 2

			// Copy data
			if dist == 0 || dist > uint32(decompPos) {
				// Invalid distance - distance of 0 or beyond current position is invalid
				break
			}
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

	return decompressed[:decompPos], nil
}

// rvaToFileOffset converts RVA to file offset
func rvaToFileOffset(peFile *pe.File, rva uint32) (uint32, error) {
	var sectionAlignment, fileAlignment uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	case *pe.OptionalHeader64:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	default:
		return 0, io.EOF
	}

	for _, section := range peFile.Sections {
		rvaAligned := align(section.SectionHeader.VirtualAddress, sectionAlignment)
		offsetAligned := align(section.SectionHeader.Offset, fileAlignment)
		vszAligned := align(section.SectionHeader.VirtualSize, sectionAlignment)
		if vszAligned > 0 && rvaAligned <= rva && rva < (rvaAligned+vszAligned) {
			offset := (rva - rvaAligned) + offsetAligned
			return offset, nil
		}
	}
	return 0, io.EOF
}

func (ASPack) Unpack(path string) (io.ReaderAt, error) {
	version := ASPack{}.Detect(path)
	if version == ASPACK_VER_NONE {
		return nil, io.EOF
	}

	// Open PE file - this gives us the original PE structure
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

	// Read entire file into memory
	fileData := make([]byte, fileSize)
	_, err = f.ReadAt(fileData, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Save original import table RVA from PE structure before unpacking
	// ASPack may have stored the original import table RVA in the PE header
	var originalImportTableRVA uint32
	var originalIATRVA uint32
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

	// Get entry point
	ep := getEP(path)
	if ep == 0 {
		return nil, io.EOF
	}

	// Read entry point code (read more to get all needed data)
	epbuff := make([]byte, 8192)
	n, err := f.ReadAt(epbuff, int64(ep))
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < 0x800 {
		return nil, io.EOF
	}

	// Read OEP from entry point buffer
	oepRVA, err := readOEPFromEPBuff(epbuff, version, ep)
	if err != nil {
		return nil, err
	}

	// Get offsets based on version
	_, blocksOffset, _, _ := getVersionOffsets(version)

	// Get PE header offsets for updating
	var peHeaderOffset, peSigOffset, entryPointOffset int
	peHeaderOffset = 0x3C
	peSigOffset = int(readUint32LE(fileData, peHeaderOffset))

	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPointOffset = peSigOffset + 4 + 20 + 16 // PE signature + COFF header + OptionalHeader offset
	case *pe.OptionalHeader64:
		entryPointOffset = peSigOffset + 4 + 20 + 16
	}

	// For version 2.1, try to unpack using the OEP we found
	if version == ASPACK_VER_21 {
		return unpackVersion21(peFile, f, fileData, epbuff, oepRVA, entryPointOffset, peSigOffset, version, ep, originalImportTableRVA, originalIATRVA)
	}

	if blocksOffset == 0 {
		// Unsupported version
		return nil, io.EOF
	}

	// For other versions (2.12, 2.42, OTHER), unpack using block structure
	return unpackOtherVersions(peFile, f, fileData, epbuff, oepRVA, entryPointOffset, peSigOffset, version, ep, blocksOffset, originalImportTableRVA, originalIATRVA)
}

// unpackVersion21 unpacks ASPack version 2.1
func unpackVersion21(peFile *pe.File, f *os.File, fileData []byte, epbuff []byte, oepRVA uint32, entryPointOffset int, peSigOffset int, version int, ep uint32, originalImportTableRVA uint32, originalIATRVA uint32) (io.ReaderAt, error) {
	// Find the .aspack section
	var aspackSectionIndex int = -1
	var originalSectionIndices []int

	for i := range peFile.Sections {
		section := peFile.Sections[i]
		name := section.Name
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		if string(name) == ".aspack" {
			aspackSectionIndex = i
		} else {
			// Keep track of original sections (excluding .aspack)
			originalSectionIndices = append(originalSectionIndices, i)
		}
	}

	if aspackSectionIndex < 0 {
		// Fallback: return original file with updated entry point
		unpackedData := make([]byte, len(fileData))
		copy(unpackedData, fileData)
		binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)
		fixImportTable(unpackedData, peFile, peSigOffset, originalImportTableRVA)
		return createTempFileFromData(unpackedData)
	}

	// Calculate the size needed for unpacked file
	// We need to estimate based on sections
	var maxRVA uint32
	var sectionAlignment, fileAlignment uint32

	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	case *pe.OptionalHeader64:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	}

	// Find the maximum RVA to estimate file size
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		endRVA := align(section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize, sectionAlignment)
		if endRVA > maxRVA {
			maxRVA = endRVA
		}
	}

	// Create unpacked file - start with a larger buffer
	estimatedSize := int(maxRVA) + 0x10000 // Add some padding
	if estimatedSize < len(fileData) {
		estimatedSize = len(fileData) * 2 // At least double the original size
	}
	unpackedData := make([]byte, estimatedSize)

	// Copy PE headers (DOS header + PE header + section headers)
	var hdrSize uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		hdrSize = optHdr.SizeOfHeaders
	case *pe.OptionalHeader64:
		hdrSize = optHdr.SizeOfHeaders
	}

	if int(hdrSize) < len(fileData) {
		copy(unpackedData, fileData[:hdrSize])
	} else {
		copy(unpackedData, fileData)
	}

	aspackSection := peFile.Sections[aspackSectionIndex]

	// Read compressed data from .aspack section
	compressedData := make([]byte, aspackSection.SectionHeader.Size)
	_, err := f.ReadAt(compressedData, int64(aspackSection.SectionHeader.Offset))
	if err != nil && err != io.EOF {
		return nil, err
	}

	// First, copy original sections as base (they may contain uncompressed data)
	// This ensures we have a valid PE structure
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		if section.SectionHeader.Size > 0 && int(section.SectionHeader.Offset) < len(fileData) {
			sectionData := make([]byte, section.SectionHeader.Size)
			n, _ := f.ReadAt(sectionData, int64(section.SectionHeader.Offset))
			if n > 0 {
				// Use the section's file offset directly
				fileOffset := section.SectionHeader.Offset
				if fileOffset+uint32(n) <= uint32(len(unpackedData)) {
					copy(unpackedData[fileOffset:], sectionData[:n])
				} else {
					// Extend buffer if needed
					neededSize := int(fileOffset + uint32(n))
					if neededSize > len(unpackedData) {
						newData := make([]byte, neededSize)
						copy(newData, unpackedData)
						unpackedData = newData
					}
					copy(unpackedData[fileOffset:], sectionData[:n])
				}
			}
		}
	}

	// Parse and decompress blocks
	// For version 2.1, we need to find the block structure in the entry point code
	blocks, err := parseCompressedBlocks(epbuff, version, ep, peFile, f, compressedData, aspackSection)
	blocksDecompressed := 0
	if err == nil && len(blocks) > 0 {
		// Decompress and write each block - this will overwrite compressed data with decompressed data
		for _, block := range blocks {
			var newData []byte
			var err error
			newData, err = decompressAndWriteBlock(block, compressedData, unpackedData, aspackSection, peFile, sectionAlignment, fileAlignment)
			if err != nil {
				// If decompression fails, continue with other blocks
				continue
			}
			blocksDecompressed++
			// Update unpackedData if buffer was extended
			if len(newData) > len(unpackedData) {
				unpackedData = newData
			}
		}
	}

	// If no blocks were found or decompressed, try alternative approach:
	// For ASPack 2.1, the entire .aspack section might need to be decompressed as a single block
	if blocksDecompressed == 0 && len(compressedData) > 0 {
		// Try to decompress the entire .aspack section
		// Estimate decompressed size based on section virtual size
		estimatedDecompressedSize := aspackSection.SectionHeader.VirtualSize
		if estimatedDecompressedSize == 0 {
			estimatedDecompressedSize = aspackSection.SectionHeader.Size * 2 // Rough estimate
		}

		// Try decompressing the compressed data
		decompressedData, err := aspackDecompress(compressedData, estimatedDecompressedSize)
		if err == nil && len(decompressedData) > 0 {
			// Write decompressed data to the .aspack section location
			aspackFileOffset := aspackSection.SectionHeader.Offset
			if int(aspackFileOffset)+len(decompressedData) <= len(unpackedData) {
				copy(unpackedData[aspackFileOffset:], decompressedData)
			} else {
				// Extend buffer if needed
				neededSize := int(aspackFileOffset) + len(decompressedData)
				if neededSize > len(unpackedData) {
					newData := make([]byte, neededSize)
					copy(newData, unpackedData)
					unpackedData = newData
				}
				copy(unpackedData[aspackFileOffset:], decompressedData)
			}
		}
	}

	// If block parsing fails or no blocks were decompressed, we still have the original sections copied above
	// This is a fallback - the original sections might already contain decompressed data

	// Fix critical PE header fields before updating entry point
	fixOptionalHeaderFields(unpackedData, peFile, peSigOffset, oepRVA)

	// Update entry point to OEP
	binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)

	// Fix import table - critical for program to run
	// Use original import table RVA if available
	fixImportTable(unpackedData, peFile, peSigOffset, originalImportTableRVA)

	// Fix IAT (Import Address Table) - this is often the cause of 0xC0000005 errors
	// Use original IAT RVA if available
	fixIAT(unpackedData, peFile, peSigOffset, originalIATRVA)

	// Fix section characteristics - remove write protection that ASPack might have added
	fixSectionCharacteristics(unpackedData, peFile, peSigOffset)

	// Fix .aspack section characteristics instead of removing it
	// Removing sections can break PE structure, so we just fix its characteristics
	fixASPackSection(unpackedData, peFile, peSigOffset)

	// Verify and fix PE checksum (optional but can help)
	fixPEChecksum(unpackedData, peSigOffset)

	// Calculate actual file size based on sections
	// Find the maximum file offset needed
	actualSize := int(hdrSize)
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		// Use the actual file offset + size
		sectionEnd := int(section.SectionHeader.Offset + section.SectionHeader.Size)
		if sectionEnd > actualSize {
			actualSize = sectionEnd
		}
	}

	// Also check if decompressed data extends beyond section boundaries
	// This can happen when sections are decompressed and grow
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		destFileOffset, err := rvaToFileOffset(peFile, section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize)
		if err == nil {
			sectionEnd := int(destFileOffset)
			if sectionEnd > actualSize {
				actualSize = sectionEnd
			}
		}
	}

	// Ensure we have enough space for decompressed data
	if actualSize < len(unpackedData) {
		// Keep the larger size to accommodate decompressed data
		actualSize = len(unpackedData)
	}

	// Align file size to file alignment (typically 512 or 4096)
	actualSize = int(align(uint32(actualSize), fileAlignment))

	// Extend buffer if needed
	if actualSize > len(unpackedData) {
		newData := make([]byte, actualSize)
		copy(newData, unpackedData)
		unpackedData = newData
	}

	// Only write the actual file size, not the entire buffer
	return createTempFileFromData(unpackedData[:actualSize])
}

// unpackOtherVersions unpacks ASPack versions other than 2.1 (2.12, 2.42, OTHER)
func unpackOtherVersions(peFile *pe.File, f *os.File, fileData []byte, epbuff []byte, oepRVA uint32, entryPointOffset int, peSigOffset int, version int, ep uint32, blocksOffset int, originalImportTableRVA uint32, originalIATRVA uint32) (io.ReaderAt, error) {
	// Find the .aspack section
	var aspackSectionIndex int = -1
	var originalSectionIndices []int

	for i := range peFile.Sections {
		section := peFile.Sections[i]
		name := section.Name
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		if string(name) == ".aspack" {
			aspackSectionIndex = i
		} else {
			// Keep track of original sections (excluding .aspack)
			originalSectionIndices = append(originalSectionIndices, i)
		}
	}

	// Get alignment parameters
	var sectionAlignment, fileAlignment uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	case *pe.OptionalHeader64:
		sectionAlignment = optHdr.SectionAlignment
		fileAlignment = optHdr.FileAlignment
	}

	// Calculate the size needed for unpacked file
	var maxRVA uint32
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		endRVA := align(section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize, sectionAlignment)
		if endRVA > maxRVA {
			maxRVA = endRVA
		}
	}

	// Create unpacked file - start with a larger buffer
	estimatedSize := int(maxRVA) + 0x10000 // Add some padding
	if estimatedSize < len(fileData) {
		estimatedSize = len(fileData) * 2 // At least double the original size
	}
	unpackedData := make([]byte, estimatedSize)

	// Copy PE headers
	var hdrSize uint32
	switch optHdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		hdrSize = optHdr.SizeOfHeaders
	case *pe.OptionalHeader64:
		hdrSize = optHdr.SizeOfHeaders
	}

	if int(hdrSize) < len(fileData) {
		copy(unpackedData, fileData[:hdrSize])
	} else {
		copy(unpackedData, fileData)
	}

	// Read compressed data from .aspack section if it exists
	var compressedData []byte
	var aspackSection *pe.Section
	if aspackSectionIndex >= 0 {
		aspackSection = peFile.Sections[aspackSectionIndex]
		compressedData = make([]byte, aspackSection.SectionHeader.Size)
		_, err := f.ReadAt(compressedData, int64(aspackSection.SectionHeader.Offset))
		if err != nil && err != io.EOF {
			return nil, err
		}
	}

	// First, copy original sections as base (they may contain uncompressed data)
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		if section.SectionHeader.Size > 0 && int(section.SectionHeader.Offset) < len(fileData) {
			sectionData := make([]byte, section.SectionHeader.Size)
			n, _ := f.ReadAt(sectionData, int64(section.SectionHeader.Offset))
			if n > 0 {
				fileOffset := section.SectionHeader.Offset
				if fileOffset+uint32(n) <= uint32(len(unpackedData)) {
					copy(unpackedData[fileOffset:], sectionData[:n])
				} else {
					// Extend buffer if needed
					neededSize := int(fileOffset + uint32(n))
					if neededSize > len(unpackedData) {
						newData := make([]byte, neededSize)
						copy(newData, unpackedData)
						unpackedData = newData
					}
					copy(unpackedData[fileOffset:], sectionData[:n])
				}
			}
		}
	}

	// Parse and decompress blocks
	blocks, err := parseCompressedBlocks(epbuff, version, ep, peFile, f, compressedData, aspackSection)
	blocksDecompressed := 0
	if err == nil && len(blocks) > 0 {
		// Decompress and write each block
		for _, block := range blocks {
			var newData []byte
			var err error
			if aspackSection != nil {
				newData, err = decompressAndWriteBlock(block, compressedData, unpackedData, aspackSection, peFile, sectionAlignment, fileAlignment)
			} else {
				// If no .aspack section, try to read compressed data from source RVA
				sourceFileOffset, err2 := rvaToFileOffset(peFile, block.SourceRVA)
				if err2 != nil {
					continue
				}
				if sourceFileOffset+block.CompressedSize > uint32(len(fileData)) {
					continue
				}
				compressedBlockData := fileData[sourceFileOffset : sourceFileOffset+block.CompressedSize]
				newData, err = decompressAndWriteBlock(block, compressedBlockData, unpackedData, nil, peFile, sectionAlignment, fileAlignment)
			}
			if err != nil {
				// If decompression fails, continue with other blocks
				continue
			}
			blocksDecompressed++
			// Update unpackedData if buffer was extended
			if len(newData) > len(unpackedData) {
				unpackedData = newData
			}
		}
	}

	// If no blocks were found or decompressed, try alternative approach:
	// Decompress the entire .aspack section as a single block
	if blocksDecompressed == 0 && aspackSection != nil && len(compressedData) > 0 {
		// Estimate decompressed size based on section virtual size
		estimatedDecompressedSize := aspackSection.SectionHeader.VirtualSize
		if estimatedDecompressedSize == 0 {
			estimatedDecompressedSize = aspackSection.SectionHeader.Size * 2 // Rough estimate
		}

		// Try decompressing the compressed data
		decompressedData, err := aspackDecompress(compressedData, estimatedDecompressedSize)
		if err == nil && len(decompressedData) > 0 {
			// Write decompressed data to the .aspack section location
			aspackFileOffset := aspackSection.SectionHeader.Offset
			if int(aspackFileOffset)+len(decompressedData) <= len(unpackedData) {
				copy(unpackedData[aspackFileOffset:], decompressedData)
			} else {
				// Extend buffer if needed
				neededSize := int(aspackFileOffset) + len(decompressedData)
				if neededSize > len(unpackedData) {
					newData := make([]byte, neededSize)
					copy(newData, unpackedData)
					unpackedData = newData
				}
				copy(unpackedData[aspackFileOffset:], decompressedData)
			}
		}
	}

	// Fix critical PE header fields before updating entry point
	fixOptionalHeaderFields(unpackedData, peFile, peSigOffset, oepRVA)

	// Update entry point to OEP
	binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)

	// Fix import table - critical for program to run
	fixImportTable(unpackedData, peFile, peSigOffset, originalImportTableRVA)

	// Fix IAT (Import Address Table)
	fixIAT(unpackedData, peFile, peSigOffset, originalIATRVA)

	// Fix section characteristics
	fixSectionCharacteristics(unpackedData, peFile, peSigOffset)

	// Fix .aspack section characteristics
	if aspackSectionIndex >= 0 {
		fixASPackSection(unpackedData, peFile, peSigOffset)
	}

	// Verify and fix PE checksum
	fixPEChecksum(unpackedData, peSigOffset)

	// Calculate actual file size based on sections
	actualSize := int(hdrSize)
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		sectionEnd := int(section.SectionHeader.Offset + section.SectionHeader.Size)
		if sectionEnd > actualSize {
			actualSize = sectionEnd
		}
	}

	// Also check if decompressed data extends beyond section boundaries
	for _, idx := range originalSectionIndices {
		section := peFile.Sections[idx]
		destFileOffset, err := rvaToFileOffset(peFile, section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize)
		if err == nil {
			sectionEnd := int(destFileOffset)
			if sectionEnd > actualSize {
				actualSize = sectionEnd
			}
		}
	}

	// Ensure we have enough space for decompressed data
	if actualSize < len(unpackedData) {
		actualSize = len(unpackedData)
	}

	// Align file size to file alignment
	actualSize = int(align(uint32(actualSize), fileAlignment))

	// Extend buffer if needed
	if actualSize > len(unpackedData) {
		newData := make([]byte, actualSize)
		copy(newData, unpackedData)
		unpackedData = newData
	}

	// Only write the actual file size, not the entire buffer
	return createTempFileFromData(unpackedData[:actualSize])
}

// parseCompressedBlocks parses compressed block information from entry point buffer
func parseCompressedBlocks(epbuff []byte, version int, epFileOffset uint32, peFile *pe.File, f *os.File, compressedData []byte, aspackSection *pe.Section) ([]CompressedBlock, error) {
	var blocks []CompressedBlock

	// For version 2.1, block structure is different
	if version == ASPACK_VER_21 {
		// Version 2.1: Blocks are usually stored in a linked list or array structure
		// We need to search for block patterns in the entry point code or compressed data

		// Try to find block information by looking for patterns
		// ASPack 2.1 often stores block count and block array
		// Look for common patterns: sequence of RVAs and sizes

		// Search in epbuff for block information
		// Blocks typically have: DestRVA (4 bytes), CompressedSize (4 bytes), DecompressedSize (4 bytes)
		for i := 0; i < len(epbuff)-16; i += 4 {
			destRVA := readUint32LE(epbuff, i)
			compSize := readUint32LE(epbuff, i+4)
			decompSize := readUint32LE(epbuff, i+8)

			// Validate: RVAs should be reasonable, sizes should be reasonable
			// For version 2.1, we need to be more lenient with validation
			if destRVA >= 0x1000 && destRVA < 0x10000000 &&
				compSize > 0 && compSize < 0x10000000 &&
				decompSize > 0 && decompSize < 0x10000000 &&
				compSize <= decompSize*2 { // Allow some compression ratio

				// Check if this RVA is in a valid section
				valid := false
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= destRVA &&
						destRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						valid = true
						break
					}
				}

				if valid {
					// Calculate source RVA in compressed data
					// For version 2.1, compressed data usually starts at the beginning of .aspack section
					// Try to find the actual source offset by looking at the compressed data structure
					// For now, use a cumulative offset based on previous blocks
					var cumulativeOffset uint32 = 0
					for _, prevBlock := range blocks {
						cumulativeOffset += prevBlock.CompressedSize
						// Align to 4-byte boundary
						cumulativeOffset = (cumulativeOffset + 3) & ^uint32(3)
					}
					sourceRVA := aspackSection.SectionHeader.VirtualAddress + cumulativeOffset

					block := CompressedBlock{
						SourceRVA:        sourceRVA,
						DestRVA:          destRVA,
						CompressedSize:   compSize,
						DecompressedSize: decompSize,
					}
					blocks = append(blocks, block)

					// Limit number of blocks to avoid infinite loop
					if len(blocks) >= 100 {
						break
					}
				}
			}
		}

		// If we found blocks, return them
		if len(blocks) > 0 {
			return blocks, nil
		}
	}

	// For other versions, use the known offsets
	_, blocksOffset, _, _ := getVersionOffsets(version)
	if blocksOffset == 0 {
		return nil, io.EOF
	}

	// Read block count (usually a DWORD at blocksOffset)
	if len(epbuff) < blocksOffset+4 {
		return nil, io.EOF
	}

	blockCount := readUint32LE(epbuff, blocksOffset)
	if blockCount == 0 || blockCount > 1000 {
		return nil, io.EOF
	}

	// Read block array (each block is typically 16 bytes: DestRVA, CompressedSize, DecompressedSize, SourceRVA)
	blockArrayOffset := blocksOffset + 4
	blockSize := 16 // Size of each block entry

	for i := uint32(0); i < blockCount; i++ {
		offset := blockArrayOffset + int(i)*blockSize
		if offset+blockSize > len(epbuff) {
			break
		}

		destRVA := readUint32LE(epbuff, offset)
		compSize := readUint32LE(epbuff, offset+4)
		decompSize := readUint32LE(epbuff, offset+8)
		sourceRVA := readUint32LE(epbuff, offset+12)

		// Validate block
		if destRVA > 0 && compSize > 0 && decompSize > 0 && compSize <= decompSize {
			block := CompressedBlock{
				SourceRVA:        sourceRVA,
				DestRVA:          destRVA,
				CompressedSize:   compSize,
				DecompressedSize: decompSize,
			}
			blocks = append(blocks, block)
		}
	}

	return blocks, nil
}

// decompressAndWriteBlock decompresses a block and writes it to the correct RVA location
// Returns the unpackedData slice (possibly extended) and error
func decompressAndWriteBlock(block CompressedBlock, compressedData []byte, unpackedData []byte, aspackSection *pe.Section, peFile *pe.File, sectionAlignment, fileAlignment uint32) ([]byte, error) {
	// Convert source RVA to file offset in compressed data
	var sourceFileOffset uint32
	if aspackSection != nil {
		if block.SourceRVA >= aspackSection.SectionHeader.VirtualAddress {
			sourceFileOffset = block.SourceRVA - aspackSection.SectionHeader.VirtualAddress
		} else {
			// Source RVA might be relative to section start
			sourceFileOffset = block.SourceRVA
		}
	} else {
		// If no aspack section, source RVA is already a file offset or needs conversion
		// Try to convert RVA to file offset
		var err error
		sourceFileOffset, err = rvaToFileOffset(peFile, block.SourceRVA)
		if err != nil {
			// If conversion fails, assume it's already a file offset
			sourceFileOffset = block.SourceRVA
		}
	}

	if sourceFileOffset+block.CompressedSize > uint32(len(compressedData)) {
		return unpackedData, io.EOF
	}

	// Read compressed block data
	compressedBlock := compressedData[sourceFileOffset : sourceFileOffset+block.CompressedSize]

	// Decompress the block
	decompressedBlock, err := aspackDecompress(compressedBlock, block.DecompressedSize)
	if err != nil {
		return unpackedData, err
	}

	// Convert destination RVA to file offset
	destFileOffset, err := rvaToFileOffset(peFile, block.DestRVA)
	if err != nil {
		// If RVA to file offset conversion fails, try to calculate based on sections
		// Find the section containing this RVA
		for _, section := range peFile.Sections {
			rvaAligned := align(section.SectionHeader.VirtualAddress, sectionAlignment)
			vszAligned := align(section.SectionHeader.VirtualSize, sectionAlignment)
			if rvaAligned <= block.DestRVA && block.DestRVA < rvaAligned+vszAligned {
				offsetAligned := align(section.SectionHeader.Offset, fileAlignment)
				destFileOffset = (block.DestRVA - rvaAligned) + offsetAligned
				break
			}
		}
		if destFileOffset == 0 {
			return unpackedData, io.EOF
		}
	}

	// Write decompressed data to file
	if destFileOffset+block.DecompressedSize <= uint32(len(unpackedData)) {
		copy(unpackedData[destFileOffset:], decompressedBlock)
		return unpackedData, nil
	}

	// Extend buffer if needed
	neededSize := int(destFileOffset + block.DecompressedSize)
	if neededSize > len(unpackedData) {
		newData := make([]byte, neededSize)
		copy(newData, unpackedData)
		unpackedData = newData
	}
	copy(unpackedData[destFileOffset:], decompressedBlock)

	return unpackedData, nil
}

// fixSectionCharacteristics fixes section characteristics that ASPack might have modified
// Also ensures sections have proper read/execute permissions
func fixSectionCharacteristics(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	// Section headers start after PE header
	var sectionHeaderOffset int
	var numSections uint16

	// Read number of sections from COFF header
	numSectionsOffset := peSigOffset + 6 // After PE signature (4 bytes) + Machine (2 bytes)
	if numSectionsOffset+2 <= len(unpackedData) {
		numSections = binary.LittleEndian.Uint16(unpackedData[numSectionsOffset:])
	}

	// Calculate section header offset
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 224 // PE sig + COFF + OptionalHeader32
	case *pe.OptionalHeader64:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 240 // PE sig + COFF + OptionalHeader64
	}

	// Fix each section header
	for i := 0; i < int(numSections) && sectionHeaderOffset+40*(i+1) <= len(unpackedData); i++ {
		sectionOffset := sectionHeaderOffset + 40*i
		// Characteristics is at offset 36 in IMAGE_SECTION_HEADER
		charOffset := sectionOffset + 36
		if charOffset+4 <= len(unpackedData) {
			// Read section name to determine section type
			sectionNameBytes := unpackedData[sectionOffset : sectionOffset+8]
			sectionName := ""
			for _, b := range sectionNameBytes {
				if b == 0 {
					break
				}
				sectionName += string(b)
			}

			currentChar := binary.LittleEndian.Uint32(unpackedData[charOffset:])

			// Remove ASPack-specific flags and restore proper characteristics
			// Remove IMAGE_SCN_MEM_DISCARDABLE if present
			currentChar &^= 0x2000000 // IMAGE_SCN_MEM_DISCARDABLE

			// Set proper characteristics based on section name
			if sectionName == ".text" || sectionName == ".code" || sectionName == ".rdata" {
				// Code sections: executable, readable
				currentChar |= 0x60000020  // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
				currentChar &^= 0x40000000 // Remove IMAGE_SCN_MEM_WRITE if set
			} else if sectionName == ".data" || sectionName == ".idata" || sectionName == ".edata" {
				// Data sections: readable, writable
				currentChar |= 0xC0000040  // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
				currentChar &^= 0x20000000 // Remove IMAGE_SCN_MEM_EXECUTE if set
			} else if sectionName == ".bss" {
				// Uninitialized data: writable
				currentChar |= 0xC0000080 // IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
			} else if sectionName == ".rsrc" {
				// Resource section: readable
				currentChar |= 0x40000040 // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
			} else {
				// For other sections, ensure at least readable
				if currentChar&0x20000000 != 0 {
					// If executable, keep it executable and readable
					currentChar |= 0x60000020
				} else {
					// Otherwise, make it readable and writable
					currentChar |= 0xC0000040
				}
			}

			// Write back the fixed characteristics
			binary.LittleEndian.PutUint32(unpackedData[charOffset:], currentChar)
		}
	}
}

// fixImportTable attempts to fix the import table in the unpacked PE file
// ASPack often stores the original import table RVA, we try to restore it
// This also updates the ImportDirectoryRVA in OptionalHeader
func fixImportTable(unpackedData []byte, peFile *pe.File, peSigOffset int, originalImportTableRVA uint32) {
	// Get data directory offset
	var dataDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirOffset = peSigOffset + 4 + 20 + 96 // PE signature + COFF header + OptionalHeader32 + DataDirectory offset
	case *pe.OptionalHeader64:
		dataDirOffset = peSigOffset + 4 + 20 + 112 // PE signature + COFF header + OptionalHeader64 + DataDirectory offset
	default:
		return
	}

	// Import table is the 2nd data directory (index 1)
	// Each data directory is 8 bytes (RVA + Size)
	importTableRVAOffset := dataDirOffset + 8 // Skip Export Table (index 0)
	importTableSizeOffset := dataDirOffset + 12

	// First, try to use the original import table RVA if provided and valid
	if originalImportTableRVA != 0 {
		// Verify the original import table is valid
		importTableFileOffset, err := rvaToFileOffset(peFile, originalImportTableRVA)
		if err == nil && importTableFileOffset < uint32(len(unpackedData)) {
			if importTableFileOffset+20 <= uint32(len(unpackedData)) {
				// Check if it looks like a valid import table
				nameRVA := readUint32LE(unpackedData, int(importTableFileOffset)+12)
				if nameRVA != 0 && nameRVA >= 0x1000 && nameRVA < 0x10000000 {
					nameFileOffset, err := rvaToFileOffset(peFile, nameRVA)
					if err == nil && int(nameFileOffset) < len(unpackedData) {
						if int(nameFileOffset)+20 <= len(unpackedData) {
							nameBytes := unpackedData[nameFileOffset : nameFileOffset+20]
							if bytes.Contains(nameBytes, []byte(".dll")) || bytes.Contains(nameBytes, []byte(".DLL")) {
								// Original import table is valid, use it!
								// Calculate size by finding the end
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
								updateImportDirectoryRVA(unpackedData, peFile, peSigOffset, originalImportTableRVA)
								return
							}
						}
					}
				}
			}
		}
	}

	// Check if import table RVA is already set and valid
	currentRVA := readUint32LE(unpackedData, importTableRVAOffset)
	currentSize := readUint32LE(unpackedData, importTableSizeOffset)

	// If import table is already set, verify it's valid by checking the actual structure
	if currentRVA != 0 && currentSize != 0 {
		// Verify it's within a valid section and the data looks valid
		valid := false
		for _, section := range peFile.Sections {
			if section.SectionHeader.VirtualAddress <= currentRVA &&
				currentRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
				// Check if we can read the import table data
				importTableFileOffset, err := rvaToFileOffset(peFile, currentRVA)
				if err == nil && importTableFileOffset < uint32(len(unpackedData)) {
					// Verify at least one valid import descriptor exists
					if importTableFileOffset+20 <= uint32(len(unpackedData)) {
						// Check first descriptor
						firstDescRVA := readUint32LE(unpackedData, int(importTableFileOffset))
						timeDateStamp := readUint32LE(unpackedData, int(importTableFileOffset)+4)
						forwarderChain := readUint32LE(unpackedData, int(importTableFileOffset)+8)
						nameRVA := readUint32LE(unpackedData, int(importTableFileOffset)+12)
						firstThunkRVA := readUint32LE(unpackedData, int(importTableFileOffset)+16)

						// If all zeros, it's an empty table (end marker) - not valid
						if firstDescRVA == 0 && timeDateStamp == 0 && forwarderChain == 0 && nameRVA == 0 && firstThunkRVA == 0 {
							valid = false
						} else {
							// Verify nameRVA points to a valid location (DLL name)
							if nameRVA != 0 && nameRVA >= 0x1000 && nameRVA < 0x10000000 {
								nameFileOffset, err := rvaToFileOffset(peFile, nameRVA)
								if err == nil && nameFileOffset < uint32(len(unpackedData)) {
									// Check if it looks like a DLL name (null-terminated string)
									if nameFileOffset+20 <= uint32(len(unpackedData)) {
										// Look for .dll extension
										nameBytes := unpackedData[nameFileOffset : nameFileOffset+20]
										if bytes.Contains(nameBytes, []byte(".dll")) || bytes.Contains(nameBytes, []byte(".DLL")) {
											valid = true
										}
									}
								}
							}
						}
					}
				}
				break
			}
		}
		if valid {
			return // Import table seems valid
		}
	}

	// Try to find import table by looking for common DLL names in sections
	// Also look for import table structure patterns (IMAGE_IMPORT_DESCRIPTOR)
	var importTableRVA uint32
	var importTableSize uint32

	commonDLLs := [][]byte{
		[]byte("kernel32.dll"),
		[]byte("KERNEL32.DLL"),
		[]byte("user32.dll"),
		[]byte("USER32.DLL"),
		[]byte("gdi32.dll"),
		[]byte("GDI32.DLL"),
		[]byte("msvcrt.dll"),
		[]byte("MSVCRT.DLL"),
	}

	// Look for DLL names and import table structures
	for _, section := range peFile.Sections {
		if section.SectionHeader.Size == 0 {
			continue
		}

		sectionData := make([]byte, section.SectionHeader.Size)
		if int(section.SectionHeader.Offset) < len(unpackedData) &&
			int(section.SectionHeader.Offset)+int(section.SectionHeader.Size) <= len(unpackedData) {
			copy(sectionData, unpackedData[section.SectionHeader.Offset:])

			// Look for DLL names and find the corresponding import descriptor
			for _, dllName := range commonDLLs {
				idx := bytes.Index(sectionData, dllName)
				if idx >= 0 {
					// Found a DLL name at idx
					// The import descriptor's Name field (offset 12) points to this DLL name
					// So we need to find a descriptor where nameRVA points to this location
					dllNameRVA := section.SectionHeader.VirtualAddress + uint32(idx)

					// Search backwards from the DLL name to find the import descriptor
					// Import descriptor is 20 bytes, Name field is at offset 12
					// So descriptor starts 12 bytes before the nameRVA field that points to dllNameRVA
					searchStart := idx
					if searchStart > 0x1000 {
						searchStart -= 0x1000 // Look back up to 4KB
					} else {
						searchStart = 0
					}

					// Search for import descriptor where nameRVA matches
					for i := searchStart; i <= idx && i+20 <= len(sectionData); i += 4 {
						// Check if this could be an import descriptor
						nameRVA := readUint32LE(sectionData, i+12)
						if nameRVA == dllNameRVA {
							// Verify this looks like a valid descriptor
							descRVA := readUint32LE(sectionData, i)
							timeDateStamp := readUint32LE(sectionData, i+4)
							forwarderChain := readUint32LE(sectionData, i+8)
							firstThunkRVA := readUint32LE(sectionData, i+16)

							// Validate descriptor fields
							if (descRVA == 0 || (descRVA >= 0x1000 && descRVA < 0x10000000)) &&
								(timeDateStamp == 0 || timeDateStamp > 0x30000000) &&
								(forwarderChain == 0 || forwarderChain == 0xFFFFFFFF) &&
								(firstThunkRVA == 0 || (firstThunkRVA >= 0x1000 && firstThunkRVA < 0x10000000)) {
								// Found valid import descriptor!
								importTableRVA = section.SectionHeader.VirtualAddress + uint32(i)

								// Calculate actual size by finding the end (all-zero descriptor)
								importTableSize = uint32(20) // At least one descriptor
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
									// Limit to reasonable size
									if importTableSize > 0x2000 {
										importTableSize = 0x2000
										break
									}
								}

								binary.LittleEndian.PutUint32(unpackedData[importTableRVAOffset:], importTableRVA)
								binary.LittleEndian.PutUint32(unpackedData[importTableSizeOffset:], importTableSize)

								// Also update ImportDirectoryRVA in OptionalHeader if needed
								updateImportDirectoryRVA(unpackedData, peFile, peSigOffset, importTableRVA)
								return
							}
						}
					}
				}
			}

			// Also look for import table patterns by verifying nameRVA points to a DLL name
			// This is more reliable than just checking field ranges
			for i := 0; i < len(sectionData)-20; i += 4 {
				// Check for potential import descriptor (20 bytes)
				descRVA := readUint32LE(sectionData, i)
				timeDateStamp := readUint32LE(sectionData, i+4)
				forwarderChain := readUint32LE(sectionData, i+8)
				nameRVA := readUint32LE(sectionData, i+12)
				firstThunkRVA := readUint32LE(sectionData, i+16)

				// Validate descriptor fields
				if (descRVA == 0 || (descRVA >= 0x1000 && descRVA < 0x10000000)) &&
					(timeDateStamp == 0 || timeDateStamp > 0x30000000) &&
					(forwarderChain == 0 || forwarderChain == 0xFFFFFFFF) &&
					nameRVA != 0 && nameRVA >= 0x1000 && nameRVA < 0x10000000 &&
					(firstThunkRVA == 0 || (firstThunkRVA >= 0x1000 && firstThunkRVA < 0x10000000)) {

					// Verify nameRVA actually points to a DLL name
					nameFileOffset, err := rvaToFileOffset(peFile, nameRVA)
					if err == nil && int(nameFileOffset) < len(unpackedData) {
						if int(nameFileOffset)+20 <= len(unpackedData) {
							nameBytes := unpackedData[nameFileOffset : nameFileOffset+20]
							// Must contain .dll or .DLL
							if bytes.Contains(nameBytes, []byte(".dll")) || bytes.Contains(nameBytes, []byte(".DLL")) {
								// Found valid import descriptor!
								importTableRVA = section.SectionHeader.VirtualAddress + uint32(i)

								// Calculate actual size by finding the end (all-zero descriptor)
								importTableSize = uint32(20)
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

								// Also update ImportDirectoryRVA in OptionalHeader if needed
								updateImportDirectoryRVA(unpackedData, peFile, peSigOffset, importTableRVA)
								return
							}
						}
					}
				}
			}
		}
	}

	// If we can't find it, don't set a fake one - leave it as is
	// Setting an invalid import table will cause access violations
	// It's better to leave it zero or use the original value if it exists
}

// updateImportDirectoryRVA updates the ImportDirectoryRVA field in OptionalHeader
// This ensures consistency between DataDirectory and OptionalHeader fields
func updateImportDirectoryRVA(unpackedData []byte, peFile *pe.File, peSigOffset int, importTableRVA uint32) {
	// Note: ImportDirectoryRVA is stored in DataDirectory[1], which we already update in fixImportTable
	// The DataDirectory is the source of truth, so we don't need to do anything extra here
	// This function is here for potential future use if needed
	_ = peFile
	_ = peSigOffset
	_ = importTableRVA
}

// fixOptionalHeaderFields fixes critical fields in OptionalHeader
// This includes AddressOfEntryPoint, ImportDirectoryRVA, RelocationDirectoryRVA, TLSDirectoryRVA
func fixOptionalHeaderFields(unpackedData []byte, peFile *pe.File, peSigOffset int, oepRVA uint32) {
	// OptionalHeader starts after COFF header (4 bytes PE sig + 20 bytes COFF)
	optHeaderOffset := peSigOffset + 4 + 20

	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		// AddressOfEntryPoint is at offset 16 in OptionalHeader32
		entryPointOffset := optHeaderOffset + 16
		if entryPointOffset+4 <= len(unpackedData) {
			binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)
		}

		// DataDirectory starts at offset 96 in OptionalHeader32
		// Import Table (index 1) is at offset 96 + 8 = 104
		// But we'll let fixImportTable handle this

		// Relocation Table (index 5) is at offset 96 + 5*8 = 136
		relocRVAOffset := optHeaderOffset + 96 + 5*8
		if relocRVAOffset+4 <= len(unpackedData) {
			currentRelocRVA := readUint32LE(unpackedData, relocRVAOffset)
			// If relocation RVA is invalid, try to find it or set to 0
			if currentRelocRVA != 0 {
				// Verify it's in a valid section
				valid := false
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= currentRelocRVA &&
						currentRelocRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						valid = true
						break
					}
				}
				if !valid {
					// Set to 0 if invalid (many executables don't need relocations)
					binary.LittleEndian.PutUint32(unpackedData[relocRVAOffset:], 0)
					binary.LittleEndian.PutUint32(unpackedData[relocRVAOffset+4:], 0)
				}
			}
		}

		// TLS Directory (index 9) is at offset 96 + 9*8 = 168
		tlsRVAOffset := optHeaderOffset + 96 + 9*8
		if tlsRVAOffset+4 <= len(unpackedData) {
			currentTLSRVA := readUint32LE(unpackedData, tlsRVAOffset)
			// If TLS RVA is invalid, set to 0
			if currentTLSRVA != 0 {
				// Verify it's in a valid section
				valid := false
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= currentTLSRVA &&
						currentTLSRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						valid = true
						break
					}
				}
				if !valid {
					// Set to 0 if invalid (most executables don't use TLS)
					binary.LittleEndian.PutUint32(unpackedData[tlsRVAOffset:], 0)
					binary.LittleEndian.PutUint32(unpackedData[tlsRVAOffset+4:], 0)
				}
			}
		}

	case *pe.OptionalHeader64:
		// AddressOfEntryPoint is at offset 16 in OptionalHeader64
		entryPointOffset := optHeaderOffset + 16
		if entryPointOffset+4 <= len(unpackedData) {
			binary.LittleEndian.PutUint32(unpackedData[entryPointOffset:], oepRVA)
		}

		// DataDirectory starts at offset 112 in OptionalHeader64
		// Relocation Table (index 5) is at offset 112 + 5*8 = 152
		relocRVAOffset := optHeaderOffset + 112 + 5*8
		if relocRVAOffset+4 <= len(unpackedData) {
			currentRelocRVA := readUint32LE(unpackedData, relocRVAOffset)
			// If relocation RVA is invalid, try to find it or set to 0
			if currentRelocRVA != 0 {
				// Verify it's in a valid section
				valid := false
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= currentRelocRVA &&
						currentRelocRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						valid = true
						break
					}
				}
				if !valid {
					// Set to 0 if invalid
					binary.LittleEndian.PutUint32(unpackedData[relocRVAOffset:], 0)
					binary.LittleEndian.PutUint32(unpackedData[relocRVAOffset+4:], 0)
				}
			}
		}

		// TLS Directory (index 9) is at offset 112 + 9*8 = 184
		tlsRVAOffset := optHeaderOffset + 112 + 9*8
		if tlsRVAOffset+4 <= len(unpackedData) {
			currentTLSRVA := readUint32LE(unpackedData, tlsRVAOffset)
			// If TLS RVA is invalid, set to 0
			if currentTLSRVA != 0 {
				// Verify it's in a valid section
				valid := false
				for _, section := range peFile.Sections {
					if section.SectionHeader.VirtualAddress <= currentTLSRVA &&
						currentTLSRVA < section.SectionHeader.VirtualAddress+section.SectionHeader.VirtualSize {
						valid = true
						break
					}
				}
				if !valid {
					// Set to 0 if invalid
					binary.LittleEndian.PutUint32(unpackedData[tlsRVAOffset:], 0)
					binary.LittleEndian.PutUint32(unpackedData[tlsRVAOffset+4:], 0)
				}
			}
		}
	}
}

// fixIAT attempts to fix the Import Address Table (IAT)
// The IAT contains the actual addresses of imported functions, which must be valid for the program to run
func fixIAT(unpackedData []byte, peFile *pe.File, peSigOffset int, originalIATRVA uint32) {
	// Get data directory offset
	var dataDirOffset int
	entrySize := 4
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirOffset = peSigOffset + 4 + 20 + 96
		entrySize = 4
	case *pe.OptionalHeader64:
		dataDirOffset = peSigOffset + 4 + 20 + 112
		entrySize = 8
	default:
		return
	}

	// IAT is the 13th data directory (index 12)
	iatRVAOffset := dataDirOffset + 12*8
	iatSizeOffset := dataDirOffset + 12*8 + 4

	// Import Table RVA (index 1)
	importTableRVAOffset := dataDirOffset + 8
	importTableRVA := readUint32LE(unpackedData, importTableRVAOffset)

	if importTableRVA == 0 {
		return // No import table, can't fix IAT
	}

	// If original IAT RVA is provided and valid, try to use it
	if originalIATRVA != 0 {
		iatFileOffset, err := rvaToFileOffset(peFile, originalIATRVA)
		if err == nil && int(iatFileOffset) < len(unpackedData) {
			// Verify it looks like a valid IAT (contains valid RVAs or zeros)
			if int(iatFileOffset)+entrySize*4 <= len(unpackedData) {
				validCount := 0
				for i := 0; i < 4 && int(iatFileOffset)+i*entrySize+entrySize <= len(unpackedData); i++ {
					addr := readUint32LE(unpackedData, int(iatFileOffset)+i*entrySize)
					if addr == 0 || (addr >= 0x1000 && addr < 0x10000000) {
						validCount++
					} else {
						break
					}
				}
				if validCount >= 2 {
					// Calculate IAT size
					iatSize := uint32(0)
					for i := 0; int(iatFileOffset)+i*entrySize+entrySize <= len(unpackedData); i++ {
						addr := readUint32LE(unpackedData, int(iatFileOffset)+i*entrySize)
						if addr == 0 {
							iatSize = uint32((i + 1) * entrySize)
							break
						}
						if addr < 0x1000 || addr >= 0x10000000 {
							iatSize = uint32(i * entrySize)
							break
						}
						iatSize = uint32((i + 1) * entrySize)
						if iatSize > 0x2000 {
							iatSize = 0x2000
							break
						}
					}
					if iatSize > 0 {
						binary.LittleEndian.PutUint32(unpackedData[iatRVAOffset:], originalIATRVA)
						binary.LittleEndian.PutUint32(unpackedData[iatSizeOffset:], iatSize)
						return
					}
				}
			}
		}
	}

	// Parse import descriptors to find IAT
	importTableFileOffset, err := rvaToFileOffset(peFile, importTableRVA)
	if err != nil {
		return
	}

	if int(importTableFileOffset) >= len(unpackedData) {
		return
	}

	var iatStartRVA uint32 = 0
	var iatEndRVA uint32 = 0

	// IMAGE_IMPORT_DESCRIPTOR is 20 bytes
	// Parse each import descriptor
	descOffset := int(importTableFileOffset)
	for descOffset+20 <= len(unpackedData) {
		// Read import descriptor fields
		// Offset 0: OriginalFirstThunk (RVA to INT - Import Name Table)
		// Offset 4: TimeDateStamp
		// Offset 8: ForwarderChain
		// Offset 12: Name (RVA to DLL name)
		// Offset 16: FirstThunk (RVA to IAT)

		firstThunkRVA := readUint32LE(unpackedData, descOffset+16)
		originalFirstThunkRVA := readUint32LE(unpackedData, descOffset)

		// If both are zero, we've reached the end
		if firstThunkRVA == 0 && originalFirstThunkRVA == 0 {
			break
		}

		// Use FirstThunk as IAT (this is what gets filled by the loader)
		// If FirstThunk is zero, use OriginalFirstThunk
		thunkRVA := firstThunkRVA
		if thunkRVA == 0 {
			thunkRVA = originalFirstThunkRVA
		}

		if thunkRVA != 0 {
			// Find the end of this IAT block (ends with zero)
			thunkFileOffset, err := rvaToFileOffset(peFile, thunkRVA)
			if err == nil && int(thunkFileOffset) < len(unpackedData) {
				// Track IAT range
				if iatStartRVA == 0 || thunkRVA < iatStartRVA {
					iatStartRVA = thunkRVA
				}

				// Find end of this thunk array
				thunkOffset := int(thunkFileOffset)
				for thunkOffset+entrySize <= len(unpackedData) {
					thunkValue := readUint32LE(unpackedData, thunkOffset)
					if entrySize == 8 {
						// For 64-bit, also check high 32 bits
						thunkValueHigh := readUint32LE(unpackedData, thunkOffset+4)
						if thunkValue == 0 && thunkValueHigh == 0 {
							break
						}
					} else {
						if thunkValue == 0 {
							break
						}
					}
					thunkOffset += entrySize
				}

				// Calculate end RVA
				thunkEndRVA := thunkRVA + uint32(thunkOffset-int(thunkFileOffset))
				if thunkEndRVA > iatEndRVA {
					iatEndRVA = thunkEndRVA
				}
			}
		}

		descOffset += 20 // Move to next descriptor
	}

	// Set IAT data directory if we found valid IAT
	if iatStartRVA != 0 && iatEndRVA > iatStartRVA {
		iatSize := iatEndRVA - iatStartRVA
		binary.LittleEndian.PutUint32(unpackedData[iatRVAOffset:], iatStartRVA)
		binary.LittleEndian.PutUint32(unpackedData[iatSizeOffset:], iatSize)

		// CRITICAL: Always ensure IAT entries match OriginalFirstThunk (INT) entries
		// IAT must contain function name/ordinal RVAs (same as INT) for loader to resolve imports
		// If IAT contains invalid addresses, it will cause access violations
		descOffset := int(importTableFileOffset)
		for descOffset+20 <= len(unpackedData) {
			firstThunkRVA := readUint32LE(unpackedData, descOffset+16)
			originalFirstThunkRVA := readUint32LE(unpackedData, descOffset)

			if firstThunkRVA == 0 && originalFirstThunkRVA == 0 {
				break
			}

			// Always copy INT to IAT if both are valid
			// IAT must contain function name/ordinal RVAs (same as INT) for loader to resolve imports
			// If IAT contains invalid addresses from decompression, this will fix them
			if firstThunkRVA != 0 && originalFirstThunkRVA != 0 {
				// Copy INT data to IAT
				intFileOffset, err1 := rvaToFileOffset(peFile, originalFirstThunkRVA)
				iatFileOffset, err2 := rvaToFileOffset(peFile, firstThunkRVA)

				if err1 == nil && err2 == nil {
					intOffset := int(intFileOffset)
					iatOffset := int(iatFileOffset)

					// If they point to the same location, data should already be correct
					// But we still verify it looks valid to catch decompression errors
					// Otherwise, copy from INT to IAT to ensure IAT has correct data
					if intFileOffset == iatFileOffset {
						// Same location - verify data looks valid
						// Valid thunk values are:
						// - 0 (end marker)
						// - 0x1000-0x7FFFFFFF (function name RVA)
						// - 0x80000000-0xFFFFFFFF (ordinal import)
						// Invalid values would be addresses like 0x00400000+ which are too high
						valid := true
						for i := 0; i < 4 && intOffset+i*entrySize+entrySize <= len(unpackedData); i++ {
							thunkValue := readUint32LE(unpackedData, intOffset+i*entrySize)
							if entrySize == 8 {
								thunkValueHigh := readUint32LE(unpackedData, intOffset+i*entrySize+4)
								if thunkValue == 0 && thunkValueHigh == 0 {
									break
								}
								// For 64-bit, check if it's a valid thunk
								// Valid: 0x1000-0x7FFFFFFF (name RVA) or 0x80000000-0xFFFFFFFF (ordinal)
								if thunkValue >= 0x1000 && thunkValue < 0x80000000 {
									// Valid name RVA
								} else if thunkValue >= 0x80000000 {
									// Valid ordinal
								} else {
									// Invalid - might be a bad address
									valid = false
									break
								}
							} else {
								if thunkValue == 0 {
									break
								}
								// Valid: 0x1000-0x7FFFFFFF (name RVA) or 0x80000000-0xFFFFFFFF (ordinal)
								if thunkValue >= 0x1000 && thunkValue < 0x80000000 {
									// Valid name RVA
								} else if thunkValue >= 0x80000000 {
									// Valid ordinal
								} else {
									// Invalid - might be a bad address
									valid = false
									break
								}
							}
						}
						// If data looks invalid, we can't fix it - skip this descriptor
						if !valid {
							descOffset += 20
							continue
						}
					} else {
						// Different locations - copy from INT to IAT
						for intOffset+entrySize <= len(unpackedData) && iatOffset+entrySize <= len(unpackedData) {
							thunkValue := readUint32LE(unpackedData, intOffset)
							if entrySize == 8 {
								thunkValueHigh := readUint32LE(unpackedData, intOffset+4)
								if thunkValue == 0 && thunkValueHigh == 0 {
									// End marker - also zero out IAT entry
									binary.LittleEndian.PutUint32(unpackedData[iatOffset:], 0)
									binary.LittleEndian.PutUint32(unpackedData[iatOffset+4:], 0)
									break
								}
								// Copy 8 bytes from INT to IAT
								binary.LittleEndian.PutUint32(unpackedData[iatOffset:], thunkValue)
								binary.LittleEndian.PutUint32(unpackedData[iatOffset+4:], thunkValueHigh)
							} else {
								if thunkValue == 0 {
									// End marker - also zero out IAT entry
									binary.LittleEndian.PutUint32(unpackedData[iatOffset:], 0)
									break
								}
								// Copy 4 bytes from INT to IAT
								binary.LittleEndian.PutUint32(unpackedData[iatOffset:], thunkValue)
							}
							intOffset += entrySize
							iatOffset += entrySize
						}
					}
				}
			} else if firstThunkRVA != 0 && originalFirstThunkRVA == 0 {
				// If FirstThunk exists but OriginalFirstThunk is zero, zero out IAT
				// This shouldn't happen in valid PE files, but handle it safely
				iatFileOffset, err := rvaToFileOffset(peFile, firstThunkRVA)
				if err == nil {
					iatOffset := int(iatFileOffset)
					// Zero out IAT entries until we find a zero or reach a limit
					for i := 0; i < 100 && iatOffset+entrySize <= len(unpackedData); i++ {
						thunkValue := readUint32LE(unpackedData, iatOffset)
						if entrySize == 8 {
							thunkValueHigh := readUint32LE(unpackedData, iatOffset+4)
							if thunkValue == 0 && thunkValueHigh == 0 {
								break
							}
							binary.LittleEndian.PutUint32(unpackedData[iatOffset:], 0)
							binary.LittleEndian.PutUint32(unpackedData[iatOffset+4:], 0)
						} else {
							if thunkValue == 0 {
								break
							}
							binary.LittleEndian.PutUint32(unpackedData[iatOffset:], 0)
						}
						iatOffset += entrySize
					}
				}
			}

			descOffset += 20
		}
		return
	}

	// Fallback: try to find IAT by pattern matching
	// This is less reliable but better than nothing
	for _, section := range peFile.Sections {
		if section.SectionHeader.Size == 0 {
			continue
		}

		sectionFileOffset, err := rvaToFileOffset(peFile, section.SectionHeader.VirtualAddress)
		if err != nil {
			continue
		}

		if int(sectionFileOffset) >= len(unpackedData) {
			continue
		}

		sectionData := make([]byte, section.SectionHeader.Size)
		if int(sectionFileOffset)+int(section.SectionHeader.Size) <= len(unpackedData) {
			copy(sectionData, unpackedData[sectionFileOffset:])
		}

		// Look for sequences of valid RVAs (potential IAT entries)
		for i := 0; i < len(sectionData)-entrySize*4; i += entrySize {
			validCount := 0
			for j := 0; j < 4 && i+j*entrySize+entrySize <= len(sectionData); j++ {
				addr := readUint32LE(sectionData, i+j*entrySize)
				if addr == 0 || (addr >= 0x1000 && addr < 0x10000000) {
					validCount++
				} else {
					break
				}
			}

			if validCount >= 3 {
				iatRVA := section.SectionHeader.VirtualAddress + uint32(i)
				// Find end
				iatSize := uint32(0)
				for k := 0; k < len(sectionData)/entrySize && i+k*entrySize+entrySize <= len(sectionData); k++ {
					addr := readUint32LE(sectionData, i+k*entrySize)
					if addr == 0 {
						iatSize = uint32((k + 1) * entrySize)
						break
					}
					if addr < 0x1000 || addr >= 0x10000000 {
						iatSize = uint32(k * entrySize)
						break
					}
					iatSize = uint32((k + 1) * entrySize)
				}
				if iatSize > 0 {
					binary.LittleEndian.PutUint32(unpackedData[iatRVAOffset:], iatRVA)
					binary.LittleEndian.PutUint32(unpackedData[iatSizeOffset:], iatSize)
					return
				}
			}
		}
	}
}

// fixPEChecksum recalculates and updates the PE checksum
// This is optional but can help with some validation issues
func fixPEChecksum(unpackedData []byte, _ int) {
	// Checksum is at offset 64 in OptionalHeader (for both 32 and 64 bit)
	var checksumOffset int
	peHeaderOffset := 0x3C
	peSigOffset := int(readUint32LE(unpackedData, peHeaderOffset))

	switch {
	case peSigOffset+4+20+64+4 <= len(unpackedData):
		// Check if it's 32-bit or 64-bit by reading magic number
		magicOffset := peSigOffset + 4 + 20
		if magicOffset+2 <= len(unpackedData) {
			magic := binary.LittleEndian.Uint16(unpackedData[magicOffset:])
			if magic == 0x10b { // PE32
				checksumOffset = peSigOffset + 4 + 20 + 64
			} else if magic == 0x20b { // PE32+
				checksumOffset = peSigOffset + 4 + 20 + 64
			}
		}
	}

	if checksumOffset > 0 && checksumOffset+4 <= len(unpackedData) {
		// Calculate PE checksum using standard algorithm
		// PE checksum is calculated over the entire file, with checksum field set to 0
		checksum := calculatePEChecksum(unpackedData, checksumOffset)
		binary.LittleEndian.PutUint32(unpackedData[checksumOffset:], checksum)
	}
}

// calculatePEChecksum calculates the PE checksum using the standard algorithm
// Algorithm: Sum all 16-bit words in the file, add the file length, then add carry bits
func calculatePEChecksum(data []byte, checksumOffset int) uint32 {
	// Set checksum field to 0 before calculation
	originalChecksum := binary.LittleEndian.Uint32(data[checksumOffset:])
	binary.LittleEndian.PutUint32(data[checksumOffset:], 0)

	var sum uint64
	fileSize := uint64(len(data))

	// Sum all 16-bit words
	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = binary.LittleEndian.Uint16(data[i:])
		} else {
			// Last byte if odd length
			word = uint16(data[i])
		}
		sum += uint64(word)
	}

	// Add file size
	sum += fileSize

	// Add carry bits (bits above 32-bit)
	for sum>>32 != 0 {
		sum = (sum & 0xFFFFFFFF) + (sum >> 32)
	}

	// Restore original checksum (in case calculation fails)
	binary.LittleEndian.PutUint32(data[checksumOffset:], originalChecksum)

	// Return checksum as 32-bit value
	return uint32(sum & 0xFFFFFFFF)
}

// fixASPackSection fixes the .aspack section characteristics instead of removing it
// Removing sections can break PE structure, so we just mark it as discardable data
func fixASPackSection(unpackedData []byte, peFile *pe.File, peSigOffset int) {
	// Read number of sections
	numSectionsOffset := peSigOffset + 6
	if numSectionsOffset+2 > len(unpackedData) {
		return
	}

	numSections := binary.LittleEndian.Uint16(unpackedData[numSectionsOffset:])
	if numSections == 0 {
		return
	}

	// Calculate section header offset
	var sectionHeaderOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 224
	case *pe.OptionalHeader64:
		sectionHeaderOffset = peSigOffset + 4 + 20 + 240
	default:
		return
	}

	// Find and fix .aspack section header
	for i := 0; i < int(numSections) && sectionHeaderOffset+40*(i+1) <= len(unpackedData); i++ {
		sectionOffset := sectionHeaderOffset + 40*i
		// Section name is at offset 0, 8 bytes
		sectionNameBytes := unpackedData[sectionOffset : sectionOffset+8]
		sectionName := ""
		for _, b := range sectionNameBytes {
			if b == 0 {
				break
			}
			sectionName += string(b)
		}

		if sectionName == ".aspack" {
			// Fix section characteristics: mark as discardable initialized data
			// This allows the loader to discard it if needed, but keeps PE structure intact
			charOffset := sectionOffset + 36
			if charOffset+4 <= len(unpackedData) {
				// IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
				newChar := uint32(0x42000040)
				binary.LittleEndian.PutUint32(unpackedData[charOffset:], newChar)
			}
			break
		}
	}
}

// createTempFileFromData creates a temporary file from byte data
func createTempFileFromData(data []byte) (io.ReaderAt, error) {
	tmpFile, err := os.CreateTemp("", "unpack_*.exe")
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
