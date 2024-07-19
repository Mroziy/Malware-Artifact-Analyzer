import pefile
import sys
import os
def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        print("== File Metadata ==")
        print("Filename:", pe.filename)
        print("File size:", pe.file_size)
        print("Creation date:", pe.get_date_timestamp())

        print("\n== PE Headers ==")
        print("Machine type:", pe.FILE_HEADER.Machine)
        print("Number of sections:", pe.FILE_HEADER.NumberOfSections)
        print("Entry point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

        print("\n== Section Information ==")
        for section in pe.sections:
            print("Name:", section.Name.decode().strip())
            print("Size:", section.SizeOfRawData)
            print("Characteristics:", section.Characteristics)
            print()

        print("\n== Import Functions ==")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print("Module:", entry.dll.decode())
            for imp in entry.imports:
                if imp.name:
                    print("Function:", imp.name.decode())

        print("\n== Export Functions ==")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print("Name:", exp.name.decode())

        print("\n== Strings ==")
        for string in pe.get_strings():
            print(string.decode())

        print("\nAnalysis complete.")

    except Exception as e:
        print("Error:", str(e))


# Usage: Provide the path to the PE file as an argument
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <pe_file_path>")
    else:
        analyze_pe(sys.argv[1])
