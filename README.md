# Unpack: A PE Unpacking Tool & Library

[English](README.md) | [中文](README_zh.md)

## Introduction
Unpack is a powerful and versatile library written in Go (Golang), designed to analyze and decompress executable files, particularly those packed with various PE (Portable Executable) packers. Packed executables are often used to obfuscate the true nature of the code, making it harder for security researchers and anti-virus software to analyze and understand the behavior of the program.

The primary goal of Unpack is to detect the presence of a packer, identify the type of packer used, and if possible, decompress the executable to its original form, allowing for easier analysis and understanding of the program's functionality.

## Background
Executable packers have been a staple in the cybersecurity landscape for years. They are used for both legitimate purposes, such as protecting intellectual property, and malicious purposes, such as hiding malware. The ability to unpack these executables is crucial for security professionals who need to analyze and understand the behavior of potentially harmful software.

## Supported Packers
Unpack currently supports the detection and unpacking of the following common PE packers:
- [x] UPX (basic support)
- [x] ASPack
- [x] FSG
- [x] Themida (basic support)
- [x] WinUpack
- [x] Petite
- [x] PESpin
- [x] Armadillo
- [x] PECompact
- [x] NSPack
- [x] MPRESS

Please note that the list above is not exhaustive, and Unpack is continuously updated to support new and emerging packers.

## Multi-Layer Packing Support

Unpack supports detecting and unpacking executables with multiple layers of packing. This means if a file is packed with multiple packers in layers (e.g., ASPack -> UPX), Unpack can:

1. **Automatically detect all layers**: Recursively detect the packer type at each layer
2. **Unpack layer by layer**: Unpack from outer to inner layers sequentially
3. **Record unpacking history**: Track packer information and version for each layer

### Usage Example

```go
package main

import (
    "fmt"
    "github.com/orcastor/unpack"
    
    // Import drivers package to register all supported packers
    _ "github.com/orcastor/unpack/drivers"
)

func main() {
    // Recursively unpack all layers (default max depth 10)
    result, err := unpack.UnpackAll("packed.exe")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    // Print unpacking history
    fmt.Println("Unpacking history:")
    for _, layer := range result.History {
        fmt.Printf("  Layer %d: %s (version %d)\n", 
            layer.Layer, layer.PackerName, layer.Version)
    }
    
    // Use unpacked data
    // result.ReaderAt contains the final unpacked file data
}
```

### Registering Packers

To use Unpack, you need to register the packers you want to support. There are two ways to do this:

**Option 1: Import all packers at once (Recommended)**
```go
import _ "github.com/orcastor/unpack/drivers"
```
This will automatically register all supported packers.

**Option 2: Import specific packers**
```go
import (
    _ "github.com/orcastor/unpack/upx"
    _ "github.com/orcastor/unpack/aspack"
    // ... import other packers as needed
)
```
This allows you to only include the packers you need, reducing binary size.

### API Reference

#### `Unpack(path string, maxDepth int) (*UnpackResult, error)`
Recursively unpacks, supporting multiple layers of packing.
- `path`: Path to the file to unpack
- `maxDepth`: Maximum unpacking depth to prevent infinite recursion, 0 means unlimited
- Returns: `UnpackResult` containing unpacked data and history information

#### `UnpackAll(path string) (*UnpackResult, error)`
Recursively unpacks all layers, default maximum depth is 10 layers.

#### `UnpackResult` Structure
```go
type UnpackResult struct {
    ReaderAt io.ReaderAt // Unpacked data
    History  []LayerInfo // Unpacking history, records information for each layer
}

type LayerInfo struct {
    PackerName string // Packer name
    Version    int    // Version number
    Layer      int    // Layer number (from outer to inner, starting from 1)
}
```

## Command Line Usage
Unpack can be used as a command-line tool to detect the type of packer, check for composite packing, and attempt to unpack the executable. Here's how you can use it:

### Building the CLI Tool
To build the command-line tool, run:

```sh
go build -o unpack.exe ./cmd/unpack
```

Or on Linux/macOS:

```sh
go build -o unpack ./cmd/unpack
```

### Installation
To install Unpack as a library, you can use the following command:
```sh
go get github.com/orcastor/unpack
```

### Commands

#### Detect Packer
Detect the packer used in an executable file:

```sh
unpack detect <path-to-executable>
```

**Example:**
```sh
unpack detect packed.exe
```

**Output:**
```
Packer detected: UPX (version 3)
File: packed.exe
```

If no packer is detected:
```
No packer detected in: packed.exe
```

#### Unpack Executable
Unpack an executable file. The tool will automatically detect and unpack all layers of packing.

**Basic usage:**
```sh
unpack unpack <path-to-executable>
```

**With custom output file:**
```sh
unpack unpack -o output.exe <path-to-executable>
```

**With custom maximum depth:**
```sh
unpack unpack -depth 5 <path-to-executable>
```

**Flags:**
- `-o string`: Output file path (default: `<input>_unpacked.exe`)
- `-depth int`: Maximum unpacking depth (0 = unlimited, default: 10)

**Examples:**
```sh
# Unpack with default settings (output: packed_unpacked.exe)
unpack unpack packed.exe

# Unpack to specific output file
unpack unpack -o unpacked.exe packed.exe

# Unpack with unlimited depth
unpack unpack -depth 0 packed.exe

# Unpack with limited depth of 3 layers
unpack unpack -depth 3 packed.exe
```

**Output example:**
```
Unpacking: packed.exe
Output: packed_unpacked.exe

Unpacking history:
  Layer 1: ASPack (version 2)
  Layer 2: UPX (version 3)

Successfully unpacked to: packed_unpacked.exe
```

#### Version
Display version information:

```sh
unpack version
```

#### Help
Display help information:

```sh
unpack help
```

Or:

```sh
unpack -h
unpack --help
```

## Contributing
Contributions to Unpack are welcome! If you have identified a new packer that is not yet supported or have improvements to the existing code, please submit a pull request or create an issue on the GitHub repository.

## License
Unpack is released under the MIT License. Feel free to use, modify, and distribute this software as you see fit.
