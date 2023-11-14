# PE Extractor for Executable

A comprehensive C++ PE (Portable Executable) file extractor designed for quickly extracting information from both executable (exe) files and dynamic link libraries (DLLs).

## Overview

This C++ program focuses on simplicity and efficiency, providing functionalities to extract information from various parts of the PE file format.

## Features

### DOS Header
Extracts information from the DOS Header of the PE file, including the e_magic, e_lfanew, and other fields.

### Rich Header
Parses and displays information from the Rich Header, providing insights into the build history of the executable.

### NT Headers
Extracts information from the NT Headers of the PE file, including the Signature, Machine, SizeOfImage, and other essential fields.

### Data Directories (within the Optional Header)
Extracts and displays information from the Data Directories within the Optional Header, covering important aspects like the Export Table, Import Table, Resource Table, and more.

### Section Headers
Parses and displays information from the Section Headers, revealing details about each section's characteristics, virtual address, and size.

### Import Table
Extracts and displays information from the Import Table, providing a list of imported functions along with the associated DLLs.

### Base Relocations Table
Extracts and displays information from the Base Relocations Table, indicating the locations that need to be adjusted when the executable is loaded into memory.

**Note:** Currently, there is no specific function for extracting the export table.

## Getting Started

### Prerequisites

- C++ compiler (supporting C++11 or later)

### Building

```bash
# Clone the repository
git clone https://github.com/Mr99ail/PE-parser.git

# Change into the project directory
cd PE-parser

# Compile the code
g++ -std=c++11 PE-parser.cpp -o PE-parser.exe
