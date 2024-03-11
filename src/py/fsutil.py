import os


def get_files_and_directories(directory):
    try:
        entries = os.listdir(directory)
        files = [
            entry for entry in entries if os.path.isfile(os.path.join(directory, entry))
        ]
        directories = [
            entry for entry in entries if os.path.isdir(os.path.join(directory, entry))
        ]
        return files, directories
    except OSError as e:
        print(f"Error accessing directory {directory}: {e}")
        return [], []


root_directory = "/home/bar0n/Downloads/"

directories_to_process = [root_directory]

file_tree = {}

while directories_to_process:
    current_directory = directories_to_process.pop()

    files, subdirectories = get_files_and_directories(current_directory)

    # Add files and subdirectories to the file tree
    file_tree[current_directory] = {"files": files, "directories": subdirectories}

    directories_to_process.extend(
        [os.path.join(current_directory, subdir) for subdir in subdirectories]
    )

print(file_tree)
