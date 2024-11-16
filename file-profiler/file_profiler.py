import os
import struct
import pefile
import lief
import math
import hashlib
from collections import Counter
from datetime import datetime

def calculate_entropy(data):
    """바이너리 데이터의 엔트로피 계산."""
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return round(entropy, 2)

def calculate_hashes(file_path):
    """파일의 MD5 및 SHA-256 해시 계산."""
    with open(file_path, "rb") as f:
        data = f.read()
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha256_hash

def is_text_file(file_path):
    """텍스트 파일 여부 확인."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.read()
        return True
    except:
        return False

def extract_strings(file_path, min_length=4):
    """파일에서 최소 길이 이상의 문자열 추출."""
    with open(file_path, "rb") as f:
        data = f.read()
    strings = [chunk.decode(errors="ignore") for chunk in data.split(b'\x00') if len(chunk) >= min_length]
    return strings

def guess_file_type(file_path):
    """파일 확장자로 파일 유형 추론."""
    extensions = {
        ".exe": "Windows Executable (PE)",
        ".dll": "Windows Dynamic Link Library (PE)",
        ".so": "Linux Shared Object (ELF)",
        ".bin": "Binary File",
        ".txt": "Text File",
        ".macho": "macOS Executable (Mach-O)"
    }
    ext = os.path.splitext(file_path)[1].lower()
    return extensions.get(ext, "Unknown Type")

def analyze_pe(file_path):
    """PE 파일 분석."""
    try:
        pe = pefile.PE(file_path)
        print("  - 운영체제 타겟: Windows")
        print(f"  - 컴파일러: {pe.OPTIONAL_HEADER.Magic}")
        
        # Import Table 출력
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            print("  - Import Table:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"    - {entry.dll.decode()}: {[imp.name.decode() if imp.name else 'Ordinal' for imp in entry.imports]}")
        
        # Export Table 출력
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            print("  - Export Table:")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"    - {exp.name.decode() if exp.name else 'Unnamed'}")
        
        # 섹션별 엔트로피 계산
        print("  - 섹션별 엔트로피:")
        for section in pe.sections:
            entropy = section.get_entropy()
            print(f"    - {section.Name.decode().strip()}: {entropy:.2f}")
        
    except Exception as e:
        print(f"[!] PE 분석 실패: {e}")

def detect_file_format(file_path):
    """파일 형식 감지."""
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic.startswith(b'MZ'):
            return "PE"
        elif magic.startswith(b'\x7fELF'):
            return "ELF"
        elif magic in [b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf']:
            return "Mach-O"
    return "알 수 없음"

def analyze_file(file_path):
    """파일 분석."""
    if not os.path.exists(file_path):
        print(f"[!] 파일을 찾을 수 없습니다: {file_path}")
        return

    print(f"[+] 파일 분석 결과: {file_path}\n")

    # 일반 정보
    file_stats = os.stat(file_path)
    file_size = file_stats.st_size
    file_modified_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    print("일반 정보:")
    print(f"  - 파일 크기: {file_size / (1024 * 1024):.2f} MB")
    print(f"  - 마지막 수정 시간: {file_modified_time}\n")

    # 엔트로피 분석
    with open(file_path, "rb") as f:
        data = f.read()
        entropy = calculate_entropy(data)
    print("엔트로피 분석:")
    print(f"  - 평균 엔트로피: {entropy}")
    if entropy > 7.5:
        print("  - 특징: 압축되었거나 난독화된 파일로 보임.\n")
    else:
        print("  - 파일이 정상적으로 보입니다.\n")

    # 해시 계산
    md5_hash, sha256_hash = calculate_hashes(file_path)
    print("해시 정보:")
    print(f"  - MD5: {md5_hash}")
    print(f"  - SHA-256: {sha256_hash}\n")

    # 파일 형식 감지
    file_format = detect_file_format(file_path)
    print("파일 형식 탐지:")
    print(f"  - 감지된 형식: {file_format}")

    if file_format == "PE":
        analyze_pe(file_path)
    elif file_format == "ELF":
        print("  - ELF 파일 분석 준비 중")
    elif file_format == "Mach-O":
        print("  - Mach-O 파일 분석 준비 중")
    else:
        if is_text_file(file_path):
            print("  - 텍스트 형식 파일로 추정됩니다.")
            strings = extract_strings(file_path)
            print("  - 첫 5줄 미리보기:")
            for string in strings[:5]:
                print(f"    - {string}")
        else:
            print("  - 파일 형식을 알 수 없습니다.")
    print("\n[✔] 분석 완료.\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("사용법: python file_profiler.py <파일 경로>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyze_file(file_path)