import os
import sys

def replace_placeholder(source_file, placeholder, replacement_file):
    try:
        # Read the replacement file
        with open(replacement_file, 'r') as replacement:
            replacement_content = replacement.read()

        # Read the source file
        with open(source_file, 'r') as source:
            source_content = source.read()

        # Replace placeholder with replacement content
        modified_content = source_content.replace(placeholder, replacement_content)

        # Get the file's extension
        file_name, file_extension = os.path.splitext(source_file)

        # Write modified content to a new file with 'modified' appended before the extension
        with open(file_name + '_modified' + file_extension, 'w') as new_file:
            new_file.write(modified_content)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

# Example usage
if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python script.py BIN_FILE PLACEHOLDER SOURCE_FILE")
        sys.exit(1)
    replacement_file = sys.argv[1]
    placeholder = sys.argv[2]
    source_file = sys.argv[3]
    replace_placeholder(source_file, placeholder, replacement_file)
