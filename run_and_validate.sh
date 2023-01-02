#!/bin/bash
# 
# Run 'chmod +x run_and_validate.sh' to add permissions
# File: run_and_validate.sh


# colours
RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

# arguments received
slices_ast_dir=$1
pattern_dir=$2

# check if slices_ast dir exists
if [ ! -d $slices_ast_dir ]; then 
	echo -e "${RED}Slices AST (${slices_ast_dir}) directory choosen does not exist.${NC}"
	exit -1

# check if patterns dir exists
elif [ ! -d $pattern_dir ]; then 
	echo -e "${RED}Patterns (${pattern_dir}) directory choosen does not exist.${NC}"
	exit -1

# all conditions are verified. run the tests
else 
	echo -e "${GREEN}running slices and patterns...${NC}"
	for input in `ls ${slices_ast_dir}`; do
		test=$(basename -s .json $input)
		echo -e "${BLUE}slices ast file: ${slice}	pattern file: ${test}.patterns.json${NC}"
		python php-analyser.py ${slices_ast_dir}/${input} ${pattern_dir}/${test}.patterns.json > /dev/null
	done

	echo -e "${GREEN}validating outputs...${NC}"
	for input in `ls our_output`; do
		echo -e "${BLUE}output: ${input}${NC}"
		python validate.py -o our_output/${input} -t real_output/${input}
		echo -e "${BLUE}========================================================${NC}"
	done
fi