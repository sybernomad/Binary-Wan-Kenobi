# Binary-Wan-Kenobi

The Binary-Wan-Kenobi is a Python script that disassembles (linear) x86/x86_64 binary files in a specified directory using the Capstone disassembly framework. It supports both ELF and PE binary formats, and outputs the disassembled instructions in a JSON format.

## Requirements

* Python 3.6 or higher
* Poetry

## Installation

To install Binary-Wan-Kenobi, run the following commands:

```
git clone git@github.com:sybernomad/Binary-Wan-Kenobi.git
cd Binary-Wan-Kenobi
poetry install
```

## Usage

```
poetry run python binary_wan_kenobi.py input_dir [output_file]
```

Arguments:

* input_dir (required): The directory containing the binary files to disassemble.
* output_file (optional): The name of the file to save the results to. If not provided, the results will be saved to a file called output.json in the current directory.

Example Usage:

```
poetry run python binary_wan_kenobi.py bins/ -o results.json
```