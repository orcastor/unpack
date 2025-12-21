// Package drivers provides a convenient way to import all supported packers at once.
// Importing this package will automatically register all packers with the unpack library.
//
// Usage:
//   import _ "github.com/orcastor/unpack/drivers"
//
// This will register all supported packers:
//   - UPX
//   - ASPack
//   - FSG
//   - WinUpack
//   - Petite
//   - PESpin
//   - Armadillo
//   - Themida
//   - PECompact
//   - NSPack
//   - MPRESS
package drivers

import (
	// Import all packer packages to trigger their init() functions
	// which register them with the unpack library
	_ "github.com/orcastor/unpack/armadillo"
	_ "github.com/orcastor/unpack/aspack"
	_ "github.com/orcastor/unpack/fsg"
	_ "github.com/orcastor/unpack/mpress"
	_ "github.com/orcastor/unpack/nspack"
	_ "github.com/orcastor/unpack/pecompact"
	_ "github.com/orcastor/unpack/pespin"
	_ "github.com/orcastor/unpack/petite"
	_ "github.com/orcastor/unpack/themida"
	_ "github.com/orcastor/unpack/upx"
	_ "github.com/orcastor/unpack/winupack"
)

