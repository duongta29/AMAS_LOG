import json

# Đường dẫn đến tệp JSON chứa từ điển
file_path = "tokens.json"

# Đọc từ điển từ tệp JSON
with open(file_path, 'r') as file:
    dictionary = json.load(file)

# Tính độ dài của từ điển
length = len(dictionary)

# In ra độ dài của từ điển
print(f"Độ dài của từ điển là: {length}")

keys = list(dictionary.keys())
for key in keys:
    with open("file_done.txt", "a") as file:
        file.write(f"{key}\n")
        