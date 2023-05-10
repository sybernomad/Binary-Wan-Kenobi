import argparse
import os
import capstone
import lief
import json


def disassemble_file(file_path):
    binary = lief.parse(file_path)

    # Determine the file format
    if binary.format == lief.EXE_FORMATS.ELF:
        code_section = binary.get_section(".text")
        start_address = code_section.virtual_address

        if code_section.content is None:
            print(f"Error: {file_path} - code section content is None")
            return {}

    elif binary.format == lief.EXE_FORMATS.PE:
        code_section = binary.section_from_rva(
            binary.optional_header.addressof_entrypoint
        )
        start_address = code_section.virtual_address

        if code_section.content is None:
            print(f"Error: {file_path} - code section content is None")
            return {}

    else:
        print(f"Error: {file_path} - unsupported file format")
        return {}

    # Create a new Capstone object with the x86_64 architecture
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    # Disassemble the code section and store the output in a dictionary
    result_dict = {}
    for instruction in md.disasm(code_section.content.tobytes(), start_address):
        if instruction.op_str:
            result_dict[
                f"0x{instruction.address:x}"
            ] = f"{instruction.mnemonic} {instruction.op_str}"
        else:
            result_dict[f"0x{instruction.address:x}"] = f"{instruction.mnemonic}"

    return result_dict


def main(input_dir, output_file="output.json"):
    # Create an empty dictionary to store the results
    results_dict = {}

    # Iterate over each file in the input directory
    for file_name in os.listdir(input_dir):
        # Disassemble the file and store the results in the dictionary
        file_path = os.path.join(input_dir, file_name)
        try:
            results_dict[file_name] = disassemble_file(file_path)
        except Exception as e:
            print(f"Unable to disassemble file {file_path}: {e}")

    # Save the results dictionary to a file
    with open(output_file, "w") as f:
        json.dump(results_dict, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="input directory containing binary files")
    parser.add_argument(
        "-o",
        "--output_file",
        default="output.json",
        help="output file for storing disassembly results (default: output.json)",
    )
    args = parser.parse_args()

    main(args.input_dir, args.output_file)
