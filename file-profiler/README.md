# File Profiler

A command-line tool for profiling and analyzing files. This tool detects the file format, calculates entropy, and provides insights into potential packing, obfuscation, or malicious characteristics.

## Features
- Supports multiple file formats: PE (Windows), ELF (Linux), Mach-O (macOS)
- Calculates Shannon entropy to detect packing or obfuscation
- Extracts metadata, linked libraries, and target OS information
- Simple and intuitive CLI interface

## Usage
```bash
python file_profiler.py <file_path>