cd ../../project/slices_ast

for FILE in *;
    do grep "\"nodeType\":" "$FILE";
done