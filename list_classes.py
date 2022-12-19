import json
import os

# gather everything in a list
dir_path = '../project/slices_ast'

slices_ast = []
for filename in os.listdir(dir_path):
    if int(filename[0]) in range(1,10):
        f = os.path.join(dir_path, filename)
        if os.path.isfile(f):
            f = open(f)
            slices_ast.append(json.load(f))
            f.close()

# iterate list of dicts and save class names
classes = {}
for slice_ast in slices_ast:
    for el in slice_ast:
        for item in el.items():
            if (type(item[1]) is not dict):
                if (item[0] == 'nodeType'):
                    classes[item[1]] = 0
            else:
                sub_el = item[1]
                for item in sub_el.items():
                    if (type(item[1]) is not dict):
                        if (item[0] == 'nodeType'):
                            classes[item[1]] = 0
                    else:
                        sub_el = item[1]
                        break
print(classes)
