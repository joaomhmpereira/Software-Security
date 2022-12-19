f = open("classes.txt", "r")
lines = f.readlines()

classes = {}
for line in lines:
    classes[line.split(":")[1][2:-3]] = 0
print(classes)