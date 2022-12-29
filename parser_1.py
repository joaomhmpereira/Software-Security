import sys, json
from AST.stmt_expr import Stmt_Expression
from AST.expr_assign import Expr_Assign
from AST.expr_variable import Expr_Variable
from AST.bexpr_greater import BExpr_Greater
from AST.bexpr_smaller import BExpr_Smaller
from AST.bexpr_equal import BExpr_Equal
from AST.bexpr_not_equal import BExpr_Not_Equal
from AST.bexpr_concat import BExpr_Concat
from AST.bexpr_plus import BExpr_Plus
from AST.stmt_if import Stmt_If
from AST.stmt_else import Stmt_Else
from AST.stmt_nop import Stmt_Nop
from AST.stmt_while import Stmt_While
from AST.stmt_break import Stmt_Break
from AST.name import Name
from AST.expr_funccall import Expr_FuncCall
from policy import Policy

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
    
    # check the number of arguments received
    if (arg != 3):
        print(bcolors.FAIL + "Usage: python parser.py <code_slice>.json <vuln_patter>.json" + bcolors.ENDC)
        sys.exit(1)

    # get ast_slice content
    try:
        with open(argv[1], 'r') as file:
            json_ast = file.read()
    except FileNotFoundError: #file doesn't exist or wrong path
        print(bcolors.FAIL + "File containing AST slice not found." + bcolors.ENDC)
        sys.exit(1)
    
    # get pattern content
    try:
       with open(argv[2], 'r') as file:
            json_pattern = file.read()
    except FileNotFoundError:
        print(bcolors.FAIL + "File containing vulnerability pattern not found." + bcolors.ENDC)
        sys.exit(1)

    parsed_pattern = json.loads(json_pattern)
    
    # create vulnerabilities from pattern
    # TODO
    # vulnerabilities = []
    
    # create policies for each vulnerability
    # policies = []
    # for vulnerability in vulnerabilities:
    #     policy = Policy(vulnerability.get_sources(), vulnerability)
    #     policies.append(policy)
        
    parsed_ast = json.loads(json_ast)
    
    # create the AST nodes for the corresponding json
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

        # <--- EXP BINARY GREATER --->
        elif (node_type == "Expr_BinaryOp_Greater"):
            print("aqui")
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Greater(left, right)
        
        # <--- EXP BINARY SMALLER --->
        elif (node_type == "Expr_BinaryOp_Smaller"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Smaller(left, right)
        
        # <--- EXP BINARY EQUAL --->
        elif (node_type == "Expr_BinaryOp_Equal"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Equal(left, right)

        # <--- EXP BINARY NOT EQUAL --->
        elif (node_type == "Expr_BinaryOp_NotEqual"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Not_Equal(left, right)

        # <--- EXP BINARY PLUS --->
        elif (node_type == "Expr_BinaryOp_Plus"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Plus(left, right)

        # <--- EXP BINARY CONCAT --->
        elif (node_type == "Expr_BinaryOp_Concat"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'])
            right = create_nodes(parsed_ast['right'])
            return BExpr_Concat(left, right)

        # <--- SCALAR LNUMBER --->
        elif (node_type == "Scalar_LNumber"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['value'])

        # <--- IF --->
        elif (node_type == "Stmt_If"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            cond = create_nodes(parsed_ast['cond'])
            stmts = create_nodes(parsed_ast['stmts'])
            elseifs = create_nodes(parsed_ast['elseifs'])
            else_clause = create_nodes(parsed_ast['else'])
            return Stmt_If(cond, stmts, elseifs, else_clause)
        
        # <--- STMT ELSE --->
        elif (node_type == "Stmt_Else"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            stmts = create_nodes(parsed_ast['stmts'])
            return Stmt_Else(stmts)
        
        # <--- FUNCTION CALL --->
        elif (node_type == "Expr_FuncCall"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            name = create_nodes(parsed_ast['name'])
            args = []
            for arg in parsed_ast['args']:
                args.append(create_nodes(arg))

            return Expr_FuncCall(name, args)

        # <--- NAME --->
        elif (node_type == "Name"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Name(parsed_ast['parts'])

        # <--- BREAK --->
        elif (node_type == "Stmt_Break"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Break(parsed_ast['num'])

        # <--- STMT NOP --->
        elif (node_type == "Stmt_Nop"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Nop()

        # <--- STMT WHILE --->
        elif (node_type == "Stmt_While"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            cond = create_nodes(parsed_ast['cond'])
            stmts = create_nodes(parsed_ast['stmts'])
            return Stmt_While(cond, stmts)
        
        else: # discard the node
            return None
        
if __name__== "__main__":
    main(sys.argv, len(sys.argv))