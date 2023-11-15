import os

# Đường dẫn đến thư mục chứa các tệp
folder_path = 'D:\Report_Log'

# Tên tệp chứa danh sách liên kết
linklist_file = 'file_done.txt'

# Đường dẫn đến tệp danh sách liên kết
# linklist_file_path = os.path.join(folder_path, linklist_file)

# Đọc danh sách liên kết từ tệp
with open(linklist_file, 'r') as file:
    linklist = [line.strip() for line in file]

# Duyệt qua các tệp trong thư mục
for file_name in os.listdir(folder_path):
    file_path = os.path.join(folder_path, file_name)

    # Kiểm tra nếu tệp là tệp JSON
    if file_name.endswith('.json'):
        # Bỏ đuôi .json
        file_name_without_extension = os.path.splitext(file_name)[0]

        # Kiểm tra nếu tên tệp không có trong danh sách liên kết
        if file_name_without_extension not in linklist:
            # Thêm vào tệp văn bản
            with open(linklist_file, 'a') as output_file:
                output_file.write(file_name_without_extension + '\n')