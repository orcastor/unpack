package unpack

import (
	"io"
	"os"
	"sync"
)

type Unpacker interface {
	Name() string
	Detect(path string) int
	Unpack(path string) (io.ReaderAt, error)
}

// UnpackResult contains unpacked data and unpacking history
type UnpackResult struct {
	ReaderAt io.ReaderAt // Unpacked data
	History  []LayerInfo // Unpacking history, records information for each layer
}

// LayerInfo records information about each packing layer
type LayerInfo struct {
	PackerName string // Packer name
	Version    int    // Version number
	Layer      int    // Layer number (from outer to inner, starting from 1)
}

var ups = sync.Map{}

func RegisterFormat(name string, unpack Unpacker) {
	ups.Store(name, unpack)
}

func DetectFormat(path string) (up Unpacker, version int) {
	ups.Range(func(k, v interface{}) bool {
		if ver := v.(Unpacker).Detect(path); ver > 0 {
			up = v.(Unpacker)
			version = ver
			return false
		}
		return true
	})
	return
}

// Unpack recursively unpacks, supporting multiple layers of packing
// maxDepth: Maximum unpacking depth to prevent infinite recursion, 0 means unlimited
func Unpack(path string, maxDepth int) (*UnpackResult, error) {
	return unpackRecursive(path, maxDepth, 0, nil)
}

// UnpackAll recursively unpacks all layers, default maximum depth is 10 layers
func UnpackAll(path string) (*UnpackResult, error) {
	return Unpack(path, 10)
}

// unpackRecursive is the internal implementation of recursive unpacking
func unpackRecursive(path string, maxDepth, currentDepth int, history []LayerInfo) (*UnpackResult, error) {
	// Check recursion depth
	if maxDepth > 0 && currentDepth >= maxDepth {
		// Reached maximum depth, return current file
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &UnpackResult{
			ReaderAt: f,
			History:  history,
		}, nil
	}

	// Detect if current file is packed
	up, version := DetectFormat(path)
	if up == nil {
		// No packing detected, return current file
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &UnpackResult{
			ReaderAt: f,
			History:  history,
		}, nil
	}

	// Record packing information of current layer
	layerInfo := LayerInfo{
		PackerName: up.Name(),
		Version:    version,
		Layer:      currentDepth + 1,
	}
	newHistory := append(history, layerInfo)

	// Perform unpacking
	unpackedData, err := up.Unpack(path)
	if err != nil {
		return nil, err
	}

	// Save unpacked data to temporary file for next layer detection
	tmpFile, err := os.CreateTemp("", "unpack_layer_*.exe")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()

	// Copy ReaderAt data to temporary file
	if err := copyReaderAtToFile(unpackedData, tmpFile); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, err
	}
	tmpFile.Close()

	// Recursively detect if unpacked file still has packing
	result, err := unpackRecursive(tmpPath, maxDepth, currentDepth+1, newHistory)
	if err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	// Check if there are deeper layers of packing
	// If returned History length equals newHistory length, no packing in next layer
	// If returned History length is greater than newHistory length, there are deeper layers
	if len(result.History) == len(newHistory) {
		// No packing in next layer, return current unpacking result
		// Close and remove temporary file since result already has ReaderAt
		if f, ok := result.ReaderAt.(*os.File); ok {
			f.Close()
		}
		os.Remove(tmpPath)
		return &UnpackResult{
			ReaderAt: unpackedData,
			History:  newHistory,
		}, nil
	}

	// There are deeper layers of packing, return recursive result
	// Clean up current layer's temporary file (result already has deeper layer's file)
	os.Remove(tmpPath)
	return result, nil
}

// copyReaderAtToFile copies the contents of ReaderAt to a file
func copyReaderAtToFile(reader io.ReaderAt, file *os.File) error {
	// Try to get ReaderAt size (if supported)
	var size int64 = -1
	if s, ok := reader.(interface{ Size() int64 }); ok {
		size = s.Size()
	}

	// Read and write using buffer
	buf := make([]byte, 64*1024) // 64KB buffer
	offset := int64(0)

	for {
		// If size is known, check if we've finished reading
		if size >= 0 && offset >= size {
			break
		}

		n, err := reader.ReadAt(buf, offset)
		if n > 0 {
			if _, writeErr := file.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			offset += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// If size is unknown and bytes read is less than buffer size, might be finished
		if size < 0 && n < len(buf) {
			break
		}
	}

	return nil
}
