import os

def count_files(dir_path):
    return len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])

# Example usage
dir_path = 'D:/ChienND/ChienND_ttp'
file_count = count_files(dir_path)
print(f'Number of files in {dir_path}: {file_count}')