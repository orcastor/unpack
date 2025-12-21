package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/orcastor/unpack/drivers"
	"github.com/orcastor/unpack"
)

const (
	version = "1.0.0"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "detect":
		handleDetect()
	case "unpack":
		handleUnpack()
	case "version", "-v", "--version":
		fmt.Printf("unpack version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Unpack - A PE Unpacking Tool

Usage:
  unpack <command> [flags] <file>

Commands:
  detect    Detect the packer used in an executable
  unpack    Unpack an executable file
  version   Show version information
  help      Show this help message

Examples:
  unpack detect packed.exe
  unpack unpack packed.exe
  unpack unpack -o unpacked.exe packed.exe

Flags for unpack:
  -o string    Output file path (default: <input>_unpacked.exe)
  -depth int   Maximum unpacking depth (0 = unlimited, default: 10)

`)
}

func handleDetect() {
	detectCmd := flag.NewFlagSet("detect", flag.ExitOnError)
	detectCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: unpack detect <file>\n")
		detectCmd.PrintDefaults()
	}

	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Error: file path required\n")
		detectCmd.Usage()
		os.Exit(1)
	}

	filePath := os.Args[2]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: file not found: %s\n", filePath)
		os.Exit(1)
	}

	up, version := unpack.DetectFormat(filePath)
	if up == nil {
		fmt.Printf("No packer detected in: %s\n", filePath)
		os.Exit(0)
	}

	fmt.Printf("Packer detected: %s (version %d)\n", up.Name(), version)
	fmt.Printf("File: %s\n", filePath)
}

func handleUnpack() {
	unpackCmd := flag.NewFlagSet("unpack", flag.ExitOnError)
	outputFile := unpackCmd.String("o", "", "Output file path")
	maxDepth := unpackCmd.Int("depth", 10, "Maximum unpacking depth (0 = unlimited)")

	unpackCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: unpack unpack [flags] <file>\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		unpackCmd.PrintDefaults()
	}

	if err := unpackCmd.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		unpackCmd.Usage()
		os.Exit(1)
	}

	args := unpackCmd.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: file path required\n")
		unpackCmd.Usage()
		os.Exit(1)
	}

	filePath := args[0]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: file not found: %s\n", filePath)
		os.Exit(1)
	}

	// Determine output file path
	outputPath := *outputFile
	if outputPath == "" {
		ext := filepath.Ext(filePath)
		base := strings.TrimSuffix(filepath.Base(filePath), ext)
		dir := filepath.Dir(filePath)
		outputPath = filepath.Join(dir, base+"_unpacked"+ext)
	}

	fmt.Printf("Unpacking: %s\n", filePath)
	fmt.Printf("Output: %s\n", outputPath)

	// Perform unpacking
	result, err := unpack.Unpack(filePath, *maxDepth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error unpacking file: %v\n", err)
		os.Exit(1)
	}

	// Print unpacking history
	if len(result.History) > 0 {
		fmt.Println("\nUnpacking history:")
		for _, layer := range result.History {
			fmt.Printf("  Layer %d: %s (version %d)\n", layer.Layer, layer.PackerName, layer.Version)
		}
	} else {
		fmt.Println("\nNo packer detected. File may already be unpacked.")
	}

	// Write unpacked data to output file
	if err := writeUnpackedData(result.ReaderAt, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully unpacked to: %s\n", outputPath)

	// Clean up if ReaderAt is a file
	if f, ok := result.ReaderAt.(*os.File); ok {
		f.Close()
	}
}

func writeUnpackedData(reader io.ReaderAt, outputPath string) error {
	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

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
			if _, writeErr := outFile.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("failed to write data: %w", writeErr)
			}
			offset += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}

		// If size is unknown and bytes read is less than buffer size, might be finished
		if size < 0 && n < len(buf) {
			break
		}
	}

	return nil
}

