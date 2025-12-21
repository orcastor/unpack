# UPX Unpacker

This package provides complete UPX unpacking support using pure Go source code implementation.

## Implementation

The UPX unpacker uses a complete pure Go implementation that:

- Detects UPX-packed PE files by searching for the "UPX!" signature
- Parses complete UPX header structure (version, method, filter, checksums, etc.)
- Implements full NRV (Not Really Vanished) decompression algorithm
- Applies UPX filters to decompressed data
- Rebuilds complete PE file structure with proper headers and sections
- Handles both PE32 and PE32+ formats

## Features

- **Pure Go**: No external dependencies, no CGO, no WASM
- **Cross-platform**: Works on all platforms supported by Go
- **Complete Decompression**: Full NRV algorithm implementation
- **Filter Support**: Handles UPX filters (with extensible support for additional filter types)
- **PE Reconstruction**: Complete PE file rebuilding with proper section alignment and headers
- **Fallback Methods**: Multiple fallback strategies when primary decompression fails

## Usage

The UPX unpacker is automatically registered when importing the package:

```go
import _ "github.com/orcastor/unpack/upx"
```

Or import the drivers package to register all packers:

```go
import _ "github.com/orcastor/unpack/drivers"
```
