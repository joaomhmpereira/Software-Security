import sys, json
from AST.stmt_expr import Stmt_Expression
from AST.expr_assign import Expr_Assign
from AST.expr_variable import Expr_Variable

# for coloured output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main(argv, arg):
    
    #check the number of arguments received
    if (arg != 3):
        print(bcolors.FAIL + "Usage: python parser.py <code_slice>.json <vuln_patter>.json" + bcolors.ENDC)
        sys.exit(1)

    #get ast_slice content
    try:
        with open(argv[1], 'r') as file:
            json_ast = file.read()
    except FileNotFoundError: #file doesn't exist or wrong path
        print(bcolors.FAIL + "File containing AST slice not found." + bcolors.ENDC)
        sys.exit(1)
    
    #try:
    #    with open(argv[2], 'r') as file:
    #        json_pattern = file.read()
    #except FileNotFoundError:
    #    print(bcolors.FAIL + "File containing vulnerability pattern not found." + bcolors.ENDC)
    #    sys.exit(1)

    #parsed_pattern = json.loads(json_pattern)

    parsed_ast = json.loads(json_ast)
    
    #create the AST nodes for the corresponding json
    create_nodes(parsed_ast)

def create_nodes(parsed_ast):
    """
    Given a json, parse it and create the corresponding AST nodes
    """
    #print(bcolors.OKBLUE + "Inside create_nodes" + bcolors.ENDC)
    if (type(parsed_ast) == list):  # if we receive a list of instructions (list of dictionaries)
        #print(bcolors.OKCYAN + "parsed_ast is a list" + bcolors.ENDC)
        instructions = []
        for instruction in parsed_ast:
            instructions.append(create_nodes(instruction)) #create the nodes for each instruction
        
        for instruction in instructions:
            print(bcolors.HEADER + "Instruction: " +  bcolors.ENDC + str(instruction))

    elif (type(parsed_ast) == dict):    # if we receive a single instruction
        #print(bcolors.OKCYAN + "parsed_ast is a dict" + bcolors.ENDC)
        # get the type of the node we're analyzing
        node_type = parsed_ast['nodeType']

        # <--- EXPRESSION --->
        if (node_type == "Stmt_Expression"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(create_nodes(parsed_ast['expr']))
        
        # <--- ASSIGNMENT --->
        elif (node_type == "Expr_Assign"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            lval = create_nodes(parsed_ast['var'])
            rval = create_nodes(parsed_ast['expr'])
            return Expr_Assign(lval, rval)
        
        # <--- VARIABLE --->
        elif (node_type == "Expr_Variable"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Expr_Variable(parsed_ast['name'])
        
        # <--- STRING --->
        elif (node_type == "Scalar_String"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['attributes']['rawValue'])

        
if __name__== "__main__":
    main(sys.argv, len(sys.argv))