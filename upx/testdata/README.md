# UPX Test Data

This directory contains test files for UPX unpacker testing.

## Test Files

### Basic Test Files

- `upx_test.exe` - Standard UPX-packed PE file
- `upx_test2.exe` - Alternative UPX-packed file for testing
- `upx_sig_start.exe` - UPX file with signature at the start
- `upx_sig_end.exe` - UPX file with signature at the end

### Edge Case Test Files

- `upx_large_test.exe` - Large UPX-packed file (>10MB)
- `upx_small_test.exe` - Small UPX-packed file (<1KB)
- `upx_filtered_test.exe` - UPX-packed file with filter applied
- `upx_method_test.exe` - UPX-packed file with different compression method

### Multi-Layer Test Files

- `upx_upx_test.exe` - File packed with UPX twice (UPX -> UPX -> Original)
- `aspack_upx_test.exe` - File packed with ASPack then UPX (ASPack -> UPX -> Original)
- `fsg_upx_test.exe` - File packed with FSG then UPX (FSG -> UPX -> Original)
- `upx_aspack_test.exe` - File packed with UPX then ASPack (UPX -> ASPack -> Original)
- `upx_fsg_test.exe` - File packed with UPX then FSG (UPX -> FSG -> Original)

### Invalid Test Files

- `not_pe.txt` - Non-PE file (should fail detection)
- `normal_pe.exe` - Normal PE file without UPX packing (should fail detection)
- `corrupted_upx.exe` - PE file with corrupted UPX header (should fail unpacking)

## Generating Test Files

To generate test files, you can use UPX command-line tool:

```bash
# Basic UPX packing
upx -o upx_test.exe original.exe

# UPX with filter
upx --filter 0x26 -o upx_filtered_test.exe original.exe

# UPX with specific method
upx -1 -o upx_method_test.exe original.exe

# Multi-layer packing (pack twice)
upx -o temp.exe original.exe
upx -o upx_upx_test.exe temp.exe
rm temp.exe

# Multi-layer with different packers
upx -o temp.exe original.exe
aspack temp.exe -o upx_aspack_test.exe
rm temp.exe
```

## Notes

- Test files are not included in the repository by default
- Tests will skip if test files don't exist
- Some test files may be large and should be added to .gitignore
- Test files should be actual PE executables for realistic testing

