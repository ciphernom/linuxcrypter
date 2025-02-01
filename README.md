# LinuxCrypter v1.0.0

LinuxCrypter is a high-performance encryption/decryption tool for Linux that rivals platforms like E4M and TrueCrypt. Designed for modern hardware, it leverages SIMD instructions and inline assembly in performance-critical sections while providing a clean C interface. This tool supports common block modes (e.g., CBC and CTR) and uses standard PKCS#7 padding to ensure data integrity.

## Overview

- **High Performance:** Processes data in 16-byte blocks with efficient SIMD operations.
- **Flexible Modes:** Supports both CBC and CTR encryption modes.
- **Robust Error Handling:** Comprehensive strategies for handling system call errors, memory allocation failures, and invalid padding.
- **Rigorous Specification:** Developed using SpecForge—a system that transforms detailed YAML specifications into working code—ensuring every implementation detail is well defined.

## SpecForge-Driven Development

The LinuxCrypter project was born from a comprehensive SpecForge YAML specification. We authored a YAML file with explicit instructions for every aspect of the tool:

- **Metadata & Header Format:** Defined the project’s name, version, and header formatting (including necessary C directives).
- **Register Usage:** Specified the roles and constraints for registers such as `rdi/rsi`, `rcx`, and `xmm0-xmm7` for efficient data processing.
- **Data Structures:** Outlined key structures including `EncryptionContext` (holding the key, IV, and mode) and `DataBuffer` (for input/output data).
- **Algorithms:** Detailed step-by-step instructions for `EncryptData` and `DecryptData` routines—including block processing, inline assembly usage, PKCS#7 padding, and cleanup.
- **Error Handling & Testing:** Enumerated error strategies for system calls, memory, and padding errors, and provided unit and integration test cases.

We used our experimental [SpecForge](#specforge) tool (written in Python) to process the YAML file and drive consistent, specification-based code generation.


## Installation

Clone the repository using git:

```bash
git clone https://github.com/ciphernom/linuxcrypter.git
cd linuxcrypter
```

Ensure you have a recent version of GCC (with support for SIMD instructions like SSE/AVX) installed on your Linux system.

## Build Instructions

Ensure you have a modern GCC with support for SIMD (e.g., SSE/AVX) and then compile the project with:

```bash
gcc -O3 -o linuxcrypter linuxcrypter.h crypto_utils.c encryption.c decryption.c main.c -march=native
```

or running unit tests, compile with the UNIT_TESTS flag:
```bash
gcc -O3 -DUNIT_TESTS -o test_linuxcrypter linuxcrypter.h crypto_utils.c encryption.c decryption.c main.c -march=native
```

## Usage
### Encrypting a File
Encrypt a file (for example, input.txt) using:

```bash
./linuxcrypter -e input.txt output.enc
```

### Decrypting a File
Decrypt the previously encrypted file with:

```bash
./linuxcrypter -d output.enc decrypted.txt
```

## Testing

Run the built-in unit tests:

./test_linuxcrypter

The tests cover scenarios such as:
- Empty Input: Ensuring that encrypting an empty buffer produces a valid padded block and that decryption recovers an empty output.
- Single Block Encryption: Validating that a 16-byte input produces an extra padding block (as per PKCS#7) and that decryption returns the original data.
- Partial Block Padding: Confirming that inputs not divisible by 16 are padded correctly.
- Invalid Padding Detection: Ensuring that corrupted ciphertext triggers the appropriate error handler.

## Project Structure
```graphql
.
├── crypto_utils.c      # SIMD and inline assembly implementations
├── crypto_utils.h      # Header for cryptographic utility functions
├── decryption.c        # Decryption routines (includes padding verification)
├── encryption.c        # Encryption routines (implements PKCS#7 padding)
├── linuxcrypter.h      # Main header file with data structures and function prototypes
├── main.c              # Command-line interface and file I/O functions
├── specforge.yaml      # The SpecForge YAML specification for LinuxCrypter
├── specforge.py        # SpecForge tool used to process the YAML file
└── README.md           # This file
```

## SpecForge
SpecForge is an experimental system that transforms YAML-based specifications into concrete implementations via Large Language Models. 
