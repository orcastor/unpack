# Unpack: PE 解包工具与库

[English](README.md) | [中文](README_zh.md)

## 简介

Unpack 是一个用 Go (Golang) 编写的强大且多功能的库，旨在分析和解压缩可执行文件，特别是那些使用各种 PE (Portable Executable) 加壳器打包的文件。打包的可执行文件通常用于混淆代码的真实性质，使安全研究人员和防病毒软件更难分析和理解程序的行为。

Unpack 的主要目标是检测加壳器的存在，识别使用的加壳器类型，并在可能的情况下将可执行文件解压缩到其原始形式，从而更容易分析和理解程序的功能。

## 背景

可执行文件加壳器多年来一直是网络安全领域的主要内容。它们既用于合法目的，如保护知识产权，也用于恶意目的，如隐藏恶意软件。对于需要分析和理解潜在有害软件行为的安全专业人员来说，解包这些可执行文件的能力至关重要。

## 支持的加壳器

Unpack 目前支持以下常见 PE 加壳器的检测和解包：
- [x] UPX (基础支持)
- [x] ASPack
- [x] FSG
- [x] Themida (基础支持)
- [x] WinUpack
- [x] Petite
- [x] PESpin
- [x] Armadillo
- [x] PECompact
- [x] NSPack
- [x] MPRESS

请注意，上述列表并非详尽无遗，Unpack 会持续更新以支持新的和新兴的加壳器。

## 多层加壳支持

Unpack 支持检测和解包多层加壳的可执行文件。这意味着如果一个文件被多个加壳器层层打包（例如：ASPack -> UPX），Unpack 可以：

1. **自动检测所有层**：递归检测每一层的加壳器类型
2. **逐层解包**：从外层到内层逐层解包
3. **记录解包历史**：跟踪每一层的加壳器信息和版本

### 使用示例

```go
package main

import (
    "fmt"
    "github.com/orcastor/unpack"
    
    // 导入 drivers 包以注册所有支持的加壳器
    _ "github.com/orcastor/unpack/drivers"
)

func main() {
    // 递归解包所有层（默认最大深度10层）
    result, err := unpack.UnpackAll("packed.exe")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    // 打印解包历史
    fmt.Println("Unpacking history:")
    for _, layer := range result.History {
        fmt.Printf("  Layer %d: %s (version %d)\n", 
            layer.Layer, layer.PackerName, layer.Version)
    }
    
    // 使用解包后的数据
    // result.ReaderAt 包含最终解包后的文件数据
}
```

### 注册加壳器

要使用 Unpack，您需要注册要支持的加壳器。有两种方式：

**方式 1：一次性导入所有加壳器（推荐）**
```go
import _ "github.com/orcastor/unpack/drivers"
```
这将自动注册所有支持的加壳器。

**方式 2：导入特定的加壳器**
```go
import (
    _ "github.com/orcastor/unpack/upx"
    _ "github.com/orcastor/unpack/aspack"
    // ... 根据需要导入其他加壳器
)
```
这允许您只包含需要的加壳器，减小二进制文件大小。

### API 说明

#### `Unpack(path string, maxDepth int) (*UnpackResult, error)`
递归解包，支持多层加壳。
- `path`: 要解包的文件路径
- `maxDepth`: 最大解包深度，防止无限递归，0 表示无限制
- 返回: `UnpackResult` 包含解包后的数据和历史信息

#### `UnpackAll(path string) (*UnpackResult, error)`
递归解包所有层，默认最大深度为 10 层。

#### `UnpackResult` 结构
```go
type UnpackResult struct {
    ReaderAt io.ReaderAt // 解包后的数据
    History  []LayerInfo // 解包历史，记录每一层的信息
}

type LayerInfo struct {
    PackerName string // 加壳器名称
    Version    int    // 版本号
    Layer      int    // 层数（从外到内，从1开始）
}
```

## 命令行使用

Unpack 可以用作命令行工具来检测加壳器类型、检查复合加壳，并尝试解包可执行文件。使用方法如下：

### 构建 CLI 工具

要构建命令行工具，请运行：

```sh
go build -o unpack.exe ./cmd/unpack
```

或在 Linux/macOS 上：

```sh
go build -o unpack ./cmd/unpack
```

### 安装

要将 Unpack 作为库安装，可以使用以下命令：

```sh
go get github.com/orcastor/unpack
```

### 命令

#### 检测加壳器

检测可执行文件中使用的加壳器：

```sh
unpack detect <path-to-executable>
```

**示例：**
```sh
unpack detect packed.exe
```

**输出：**
```
Packer detected: UPX (version 3)
File: packed.exe
```

如果未检测到加壳器：
```
No packer detected in: packed.exe
```

#### 解包可执行文件

解包可执行文件。工具会自动检测并解包所有加壳层。

**基本用法：**
```sh
unpack unpack <path-to-executable>
```

**指定输出文件：**
```sh
unpack unpack -o output.exe <path-to-executable>
```

**指定最大深度：**
```sh
unpack unpack -depth 5 <path-to-executable>
```

**参数：**
- `-o string`: 输出文件路径（默认：`<input>_unpacked.exe`）
- `-depth int`: 最大解包深度（0 = 无限制，默认：10）

**示例：**
```sh
# 使用默认设置解包（输出：packed_unpacked.exe）
unpack unpack packed.exe

# 解包到指定输出文件
unpack unpack -o unpacked.exe packed.exe

# 无限制深度解包
unpack unpack -depth 0 packed.exe

# 限制深度为 3 层
unpack unpack -depth 3 packed.exe
```

**输出示例：**
```
Unpacking: packed.exe
Output: packed_unpacked.exe

Unpacking history:
  Layer 1: ASPack (version 2)
  Layer 2: UPX (version 3)

Successfully unpacked to: packed_unpacked.exe
```

#### 版本信息

显示版本信息：

```sh
unpack version
```

#### 帮助信息

显示帮助信息：

```sh
unpack help
```

或：

```sh
unpack -h
unpack --help
```

## 贡献

欢迎对 Unpack 做出贡献！如果您发现了一个尚未支持的新加壳器，或者对现有代码有改进，请在 GitHub 仓库上提交 pull request 或创建 issue。

## 许可证

Unpack 在 MIT 许可证下发布。您可以自由使用、修改和分发此软件。

