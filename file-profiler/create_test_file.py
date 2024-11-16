import os
import struct

def create_test_files():
    """현실적인 테스트 파일 생성."""
    base_dir = "test_files"
    os.makedirs(base_dir, exist_ok=True)

    # Simple text file
    with open(os.path.join(base_dir, "test.txt"), "w") as f:
        f.write("This is a simple text file.\n" * 10)

    # Binary file with high entropy
    with open(os.path.join(base_dir, "packed.bin"), "wb") as f:
        f.write(os.urandom(1024))  # 1KB of random data

    # Valid PE file (Windows Portable Executable)
    with open(os.path.join(base_dir, "dummy.exe"), "wb") as f:
        f.write(b"MZ")  # DOS Header magic number
        f.write(b"\x00" * 58)  # Padding
        f.write(struct.pack("<I", 64))  # e_lfanew (offset to PE Header)
        f.write(b"PE\0\0")  # PE Signature
        f.write(b"\x4c\x01")  # Machine type (Intel 386)
        f.write(b"\x01\x00")  # Number of sections
        f.write(b"\x00" * 20)  # Remaining header fields
        f.write(b".text")  # Section name
        f.write(b"\x00" * 12)  # Padding
        f.write(b"\x00" * 40)  # Section data

    # Valid ELF file (Linux Executable and Linkable Format)
    with open(os.path.join(base_dir, "dummy.elf"), "wb") as f:
        f.write(b"\x7fELF")  # ELF magic number
        f.write(b"\x02\x01\x01")  # 64-bit, little-endian, ELF version
        f.write(b"\x00" * 9)  # Padding
        f.write(struct.pack("<H", 2))  # Type (Executable file)
        f.write(struct.pack("<H", 62))  # Machine (x86-64)
        f.write(struct.pack("<I", 1))  # ELF version
        f.write(b"\x00" * 8)  # Entry point
        f.write(b"\x00" * 8)  # Program header offset
        f.write(b"\x00" * 8)  # Section header offset
        f.write(b"\x00" * 4)  # Flags
        f.write(b"\x00" * 16)  # Padding

    # Valid Mach-O file (macOS Mach Object)
    with open(os.path.join(base_dir, "dummy.macho"), "wb") as f:
        f.write(b"\xcf\xfa\xed\xfe")  # Mach-O magic number
        f.write(struct.pack("<I", 0xfeedface))  # CPU type (x86)
        f.write(struct.pack("<I", 7))  # CPU subtype
        f.write(struct.pack("<I", 2))  # File type (Executable)
        f.write(struct.pack("<I", 1))  # Number of load commands
        f.write(struct.pack("<I", 32))  # Size of commands
        f.write(struct.pack("<I", 0))  # Flags
        f.write(b"\x00" * 16)  # Padding

    print(f"[✔] 테스트 파일이 '{base_dir}' 디렉토리에 생성되었습니다.")

    # 간단한 생성 요약 출력
    print("\n[+] 생성된 파일 목록 및 특징:")
    print("  - test.txt: 간단한 텍스트 파일")
    print("  - packed.bin: 높은 엔트로피의 바이너리 파일 (압축/난독화 시뮬레이션)")
    print("  - dummy.exe: Windows PE 파일 (PE Header 포함)")
    print("  - dummy.elf: Linux ELF 파일 (ELF Header 포함)")
    print("  - dummy.macho: macOS Mach-O 파일 (Mach-O Header 포함)")

if __name__ == "__main__":
    create_test_files()