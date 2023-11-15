import json

def read_dicts_from_file(file_path):
    data = {}
    with open(file_path, 'r') as file:
        file_content = file.read()
        dicts = file_content.split('}{')
        dicts[0] = dicts[0] + '}'
        dicts[-1] = '{' + dicts[-1]
        for d in dicts:
            if d.find('{') == -1:
                d = '{' + d
            if d.find('}') == -1:
                d = d + '}'
            d = json.loads(d)
            for key, value in d.items():
                data[key] = value
            # data[d[0]] = d[1]
        # dicts = [json.loads(d) for d in dicts]
        return data

file_path = 'tokens.txt'
dicts = read_dicts_from_file(file_path)
with open("test.json", "w") as f:
    json.dump(dicts, f)