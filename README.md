# Unpack: A PE Unpacking Tool & Library

## Introduction
Unpack is a powerful and versatile library written in Go (Golang), designed to analyze and decompress executable files, particularly those packed with various PE (Portable Executable) packers. Packed executables are often used to obfuscate the true nature of the code, making it harder for security researchers and anti-virus software to analyze and understand the behavior of the program.

The primary goal of Unpack is to detect the presence of a packer, identify the type of packer used, and if possible, decompress the executable to its original form, allowing for easier analysis and understanding of the program's functionality.

## Background
Executable packers have been a staple in the cybersecurity landscape for years. They are used for both legitimate purposes, such as protecting intellectual property, and malicious purposes, such as hiding malware. The ability to unpack these executables is crucial for security professionals who need to analyze and understand the behavior of potentially harmful software.

## Supported Packers
Unpack currently supports the detection and unpacking of the following common PE packers:
- [ ] UPX
- [ ] ASPack
- [ ] FSG
- [ ] Themida
- [ ] WinUpack
- [ ] Petite
- [ ] PESpin
- [ ] Armadillo

Please note that the list above is not exhaustive, and Unpack is continuously updated to support new and emerging packers.

## Command Line Usage
Unpack can be used as a command-line tool to detect the type of packer, check for composite packing, and attempt to unpack the executable. Here's how you can use it:

### Installation
To install Unpack, you can use the following command:
```sh
go get github.com/orcastor/unpack
```

### Detect Packer
To detect the packer used in an executable:

```sh
unpack detect <path-to-executable>
```

### Unpack Executable
To attempt to unpack the executable:

```sh
unpack unpack <path-to-executable>
```

## Contributing
Contributions to Unpack are welcome! If you have identified a new packer that is not yet supported or have improvements to the existing code, please submit a pull request or create an issue on the GitHub repository.

## License
Unpack is released under the MIT License. Feel free to use, modify, and distribute this software as you see fit.
