package aspack

import (
	"bytes"
	"debug/pe"
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

// getEP 获取PE文件入口点的文件偏移量
func getEP(path string) uint32 {
	// 解析PE文件
	peFile, err := pe.Open(path)
	if err != nil {
		return 0
	}

	// 获取PE头大小 (假设从 OptionalHeader 里获取)
	var hdrSize uint32
	// 获取入口点地址 (RVA)
	var entryPoint uint32
	// 获取对齐参数
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

	// 处理RVA小于PE头大小的情况
	if entryPoint < hdrSize {
		return entryPoint
	}

	// 遍历PE文件的节，查找包含入口点的节，并计算文件偏移量
	for _, section := range peFile.Sections {
		rvaAligned := align(section.VirtualAddress, sectionAlignment)
		offsetAligned := align(section.Offset, fileAlignment)
		vszAligned := align(section.VirtualSize, sectionAlignment)
		if vszAligned > 0 && rvaAligned <= entryPoint && entryPoint < (rvaAligned+vszAligned) {
			offset := (entryPoint - rvaAligned) + offsetAligned
			if section.Name == ".aspack" {
				return offset
			}
		}
	}

	return 0
}

type ASPack struct{}

func (ASPack) Name() string {
	return "ASPack"
}

func (ASPack) Detect(path string) int {
	ep := getEP(path)

	f, _ := os.Open(path)
	epbuff := make([]byte, 4096)
	_, _ = f.ReadAt(epbuff, int64(ep))

	// 查找匹配的版本
	if bytes.Equal(epbuff[ASPACK_EPBUFF_OFFSET_21:ASPACK_EPBUFF_OFFSET_21+6], []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}) {
		return ASPACK_VER_21
	} else if bytes.Equal(epbuff[ASPACK_EPBUFF_OFFSET_212:ASPACK_EPBUFF_OFFSET_212+6], []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}) {
		return ASPACK_VER_212
	} else if bytes.Equal(epbuff[ASPACK_EPBUFF_OFFSET_OTHER:ASPACK_EPBUFF_OFFSET_OTHER+6], []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}) {
		return ASPACK_VER_OTHER
	} else if bytes.Equal(epbuff[ASPACK_EPBUFF_OFFSET_242:ASPACK_EPBUFF_OFFSET_242+6], []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}) {
		return ASPACK_VER_242
	}
	return 0
}

func (ASPack) Unpack(path string) (io.ReaderAt, error) {
	return nil, nil
}
