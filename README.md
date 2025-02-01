# LinuxCrypter v2.0.0

LinuxCrypter is a secure encryption/decryption tool for Linux that implements AES-256 encryption using hardware acceleration. It leverages AES-NI instructions for both security and performance while providing a clean C interface. This tool supports common block modes (CBC and CTR) and uses standard PKCS#7 padding.

This project was written in 2 HOURS by SpecForge, O3 and Claude.

## Features

- **Hardware-Accelerated AES-256:** Uses AES-NI instructions for optimal security and performance
- **Secure Block Modes:** Supports both CBC and CTR encryption modes
- **Secure Key Management:** Proper key schedule handling and secure cleanup
- **PKCS#7 Padding:** Standard-compliant padding with constant-time verification
- **Random IV Generation:** Secure IV generation using /dev/urandom
- **Robust Error Handling:** Comprehensive error checking and secure cleanup on failures

## Development History

### Initial Version (v1.0.0) - SpecForge Origins
The LinuxCrypter project was initially born from a comprehensive SpecForge YAML specification. The original implementation used a custom block cipher and was developed using the experimental SpecForge system—a tool that transforms detailed YAML specifications into working code using Large Language Models.

The initial specification included:
- **Metadata & Header Format:** Defined the project's name, version, and header formatting
- **Register Usage:** Specified register allocation for SIMD operations
- **Data Structures:** Outlined key structures for encryption context and data buffers
- **Algorithms:** Detailed the encryption/decryption routines and padding schemes
- **Error Handling & Testing:** Provided comprehensive test cases and error strategies

### Security Audit and Improvements (v2.0.0)
After review and discussion, several critical security improvements were implemented:

1. **Replaced Custom Cipher:**
   - Removed the original XOR-based cipher
   - Implemented proper AES-256 using hardware acceleration
   - Added proper key schedule management

2. **Enhanced Security Features:**
   - Added secure random IV generation
   - Implemented constant-time padding verification
   - Added secure cleanup of sensitive data
   - Improved memory handling with barriers

3. **Improved Key Management:**
   - Added dedicated key file handling
   - Implemented proper key schedule expansion
   - Added secure key cleanup routines

These improvements transformed LinuxCrypter from an educational project into a more security-focused tool, though we still recommend established cryptographic libraries for production use.

## Build Instructions

Ensure you have GCC with AES-NI support installed:

```bash
gcc -Wall -O2 -maes -msse4 main.c encryption.c decryption.c crypto_utils.c -o linuxcrypter
```

## Usage

### Generate an Encryption Key
First, generate a 32-byte (256-bit) key:
```bash
dd if=/dev/urandom of=key.bin bs=32 count=1
```

### Encrypting a File
```bash
./linuxcrypter -e input.txt encrypted.bin key.bin
```

### Decrypting a File
```bash
./linuxcrypter -d encrypted.bin decrypted.txt key.bin
```

## Security Features

- **AES-256 Implementation:**
  - Hardware-accelerated using AES-NI instructions
  - Full 14-round implementation
  - Proper key expansion algorithm

- **Secure Key Handling:**
  - Keys are stored in expanded form for performance
  - Secure cleanup of sensitive material
  - Memory barriers to prevent optimization of security-critical operations

- **IV Handling:**
  - Random IV generation for each encryption
  - IV is prepended to encrypted output
  - Proper IV extraction during decryption

- **Constant-Time Operations:**
  - Padding verification is constant-time
  - AES operations use constant-time hardware instructions
  - No timing side-channels in critical paths

## Project Structure
```
.
├── crypto_utils.c    # AES-256 implementation using AES-NI
├── crypto_utils.h    # Key schedule and block operation definitions
├── decryption.c     # Decryption with constant-time padding verification
├── encryption.c     # Encryption with PKCS#7 padding
├── linuxcrypter.h   # Main header with data structures
└── main.c          # CLI interface and file handling
```

## Testing

The project includes unit tests that verify:
- Empty input handling
- Single block encryption/decryption
- Partial block padding
- Invalid padding detection
- Key schedule initialization
- Secure cleanup operations

Run the unit tests:
```bash
# Compile with test flag
gcc -Wall -O2 -maes -msse4 -DUNIT_TESTS main.c encryption.c decryption.c crypto_utils.c -o linuxcrypter_test

# Run tests
./linuxcrypter_test
```

The tests cover scenarios such as:
- Empty Input: Ensuring that encrypting an empty buffer produces a valid padded block and that decryption recovers an empty output.
- Single Block Encryption: Validating that a 16-byte input produces an extra padding block (as per PKCS#7) and that decryption returns the original data.
- Partial Block Padding: Confirming that inputs not divisible by 16 are padded correctly.
- Invalid Padding Detection: Ensuring that corrupted ciphertext triggers the appropriate error handler.

## Security Notes

While this implementation uses strong cryptographic primitives and hardware acceleration, for production use consider:
- Adding authentication (e.g., using HMAC or switching to AES-GCM)
- Using a key derivation function for password-based encryption
- Adding additional integrity checks for encrypted data
- Using established cryptographic libraries like OpenSSL for critical applications

## Requirements

- Linux system with x86-64 CPU supporting AES-NI instructions
- GCC compiler with SIMD support
- 32 bytes of secure random data for the encryption key

## About SpecForge

SpecForge is an experimental system that transforms YAML-based specifications into concrete implementations via Large Language Models. While the initial version of LinuxCrypter was developed using SpecForge, the current version (v2.0.0) has evolved through manual review and security-focused improvements.

The LinuxCrypter project demonstrates both the potential and limitations of specification-driven development using LLMs. The initial implementation, while functional, required significant security improvements and expert review to reach a more secure state. This journey from generated code to hardened implementation provides valuable insights into the role of AI in security-critical software development.

## License

This project is provided as-is for educational purposes. Review security implications before using in production environments.
