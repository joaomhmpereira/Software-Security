import sys, json
from AST.stmt_expr import Stmt_Expression
from AST.expr_assign import Expr_Assign
from AST.expr_variable import Expr_Variable
from AST.stmt_if import Stmt_If
from AST.stmt_else import Stmt_Else
from AST.stmt_nop import Stmt_Nop
from AST.stmt_while import Stmt_While
from AST.stmt_break import Stmt_Break
from AST.name import Name
from AST.arg import Arg
from AST.expr_funccall import Expr_FuncCall
from AST.symbol_table import Symbol_Table
from AST.binopexpr import Binop_Expr
from policy import Policy
from vulnerability import Vulnerability
from copy import deepcopy

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

    parsed_patterns = json.loads(json_pattern)
    parsed_ast = json.loads(json_ast)

    # get output filename
    # slices_ast/1a-basic-flow.json -> output/1a-basic-flow.output.json
    B = [x for x in argv[1].split('/') if x.strip()]
    B = [x for x in B[1].split('.') if x.strip()]
    output_file = 'our_output/' + B[0] + '.output.json'
    
    # create vulnerabilities from pattern
    vulnerabilities = []
    for pattern in parsed_patterns:
        vulnerabilities.append(Vulnerability(pattern['vulnerability'], pattern['sources'], pattern['sanitizers'], pattern['sinks'], pattern['implicit'], output_file))

    # create policies for each vulnerability
    policies = []
    for vulnerability in vulnerabilities:
        policy = Policy(vulnerability.get_sources(), vulnerability)
        policies.append(policy)
        print(policy)
    
    output = [] 
    for policy in policies:
        print(policy)
        # create the AST nodes for the corresponding json
        symbol_table = Symbol_Table()
        create_nodes(parsed_ast, symbol_table, policy)
        output += policy.get_vulnerability().output
        print("NEW POLICY")
    
    with open(output_file, 'w') as outfile:
        json.dump(output, outfile, ensure_ascii=False, indent=4)
        
def create_nodes(parsed_ast, symbol_table=None, policy=None):
    """
    Given a json, parse it and create the corresponding AST nodes
    """
    # print s
    # if symbol_table:
    #     print(bcolors.OKCYAN + "=======")
    #     print(symbol_table)
    #     print("=======" + bcolors.ENDC)

    #print(bcolors.OKBLUE + "Inside create_nodes" + bcolors.ENDC)
    if (type(parsed_ast) == list):  # if we receive a list of instructions (list of dictionaries)
        #print(bcolors.OKCYAN + "parsed_ast is a list" + bcolors.ENDC)
        instructions = []
        for instruction in parsed_ast:
            instructions.append(create_nodes(instruction, symbol_table, policy)) #create the nodes for each instruction

        for instruction in instructions:
            print(bcolors.HEADER + "Instruction: " +  bcolors.ENDC + str(instruction))
        return instructions

    elif (type(parsed_ast) == dict):    # if we receive a single instruction
        #print(bcolors.OKCYAN + "parsed_ast is a dict" + bcolors.ENDC)
        # get the type of the node we're analyzing
        node_type = parsed_ast['nodeType']

        # <--- EXPRESSION --->
        if (node_type == "Stmt_Expression"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(create_nodes(parsed_ast['expr'], symbol_table, policy))
        
        # <--- ASSIGNMENT --->
        elif (node_type == "Expr_Assign"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            rval = create_nodes(parsed_ast['expr'], symbol_table, policy)
            lval = create_nodes(parsed_ast['var'], symbol_table, policy)
            
            # initialized variables: remove from source
            if not lval.is_source():
                lval.del_source(lval.name)

            #print(bcolors.WARNING + str(rval) + bcolors.ENDC)
             
            sources = policy.lub(lval.get_sources(), rval.get_sources())

            sanitized_sources = policy.lub(lval.get_sanitized_sources(), rval.get_sanitized_sources())
            lval.set_sources(sources)
            print("SOURCES: " + str(lval.get_sources()))
            for sanitizer in rval.get_sanitizers():
                if sanitizer not in lval.sanitizers:
                    lval.sanitizers.append(sanitizer)

            lval.set_sanitized_sources(sanitized_sources)
            print("SANITIZED SOURCES: " + str(sanitized_sources))

            # explicit leaks
            if lval.is_sink():
                for source in rval.get_sources():
                    #print(bcolors.HEADER + "Outputing vuln without san flows" + bcolors.ENDC)
                    source_copy = deepcopy(source)
                    policy.get_vulnerability().add_instance(source_copy, lval.get_name(), True, [])                            
                
                for sanitized_source in rval.get_sanitized_sources():
                    #print(bcolors.HEADER + "Outputing vuln witho san flows" + bcolors.ENDC)
                    #print(bcolors.WARNING + "SANITIZERS ASSIGNMENT: " + str(rval.get_sanitizers()) + bcolors.ENDC)
                    sanitized_source_copy = deepcopy(sanitized_source)
                    sanitizers_list_copy = deepcopy(rval.get_sanitizers())
                    policy.get_vulnerability().add_instance(sanitized_source_copy, lval.get_name(), False, sanitizers_list_copy)

            return Expr_Assign(lval, rval)
        
        # <--- VARIABLE --->
        elif (node_type == "Expr_Variable"):
            #print(parsed_ast)
            name = "$" + parsed_ast['name']
            print(bcolors.OKGREEN + node_type + " -> " + name + bcolors.ENDC)
            variable = symbol_table.get_variable(name)
            
            if variable is None:
                print('variable is not in symtable')
                variable = Expr_Variable(name, policy.get_vultype(name))
                symbol_table.add_variable(variable)
            return variable
        
        # <--- STRING --->
        elif (node_type == "Scalar_String"):
            #print(parsed_ast)
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['attributes']['rawValue'])

        # <--- BINARY EXPRESSIONS --->
        elif ("Expr_BinaryOp" in node_type):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, policy)
            expr = Binop_Expr(left, right)
            
            expr.set_sources(policy.lub(left.get_sources(), right.get_sources()))
            expr.set_sanitized_sources(policy.lub(left.get_sanitized_sources(), right.get_sanitized_sources()))
            sanitizers = []
            for sanitizer in left.get_sanitizers() + right.get_sanitizers():
                if sanitizer not in sanitizers:
                    sanitizers.append(sanitizer)        
            expr.set_sanitizers(sanitizers)
            return expr

        # <--- SCALAR LNUMBER --->
        elif (node_type == "Scalar_LNumber"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['value'])

        # <--- IF --->
        elif (node_type == "Stmt_If"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            #print(bcolors.OKBLUE + "SYMBOL TABLE BEFORE" + str(symbol_table) + bcolors.ENDC)
            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            
            symbol_table_if = deepcopy(symbol_table)
            symbol_table_else = deepcopy(symbol_table)
                        
            stmts = create_nodes(parsed_ast['stmts'], symbol_table_if, policy)
            else_clause = create_nodes(parsed_ast['else'], symbol_table_else, policy)
            
            # print(bcolors.WARNING + "IF symtable " + str(symbol_table_if) + bcolors.ENDC)
            # print(bcolors.WARNING + "ELSE symtable " + str(symbol_table_else) + bcolors.ENDC)

            merged_symbol_table, common_variables = symbol_table_if.merge_symbols(symbol_table_else, policy)
            # print(bcolors.FAIL + "Merged Symbol Table: " + str(merged_symbol_table) + bcolors.ENDC)
            # print(bcolors.OKBLUE + "InBoth: " + str(common_variables) + bcolors.ENDC)

            symbol_table.add_missing_variables(merged_symbol_table, common_variables)
            #print(bcolors.OKBLUE + "SYMBOL TABLE AFTER" + str(symbol_table) + bcolors.ENDC)
            
            """
            TODO: handle elseifs
            """
            #elseif_list = parsed_ast['elseifs']
            #elseifs = []
            #symbol_table_elseifs = []
            #for elseif in elseif_list:
            #    symbol_table_elseif = deepcopy(symbol_table)
            #    elseifs.append(create_nodes(elseif, symbol_table_elseif, policy))
            #    symbol_table_elseifs.append(symbol_table_elseif)
            
            return Stmt_If(cond, stmts, [], else_clause)

        # <--- STMT ELSE --->
        elif (node_type == "Stmt_Else"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            stmts = create_nodes(parsed_ast['stmts'], symbol_table, policy)
            return Stmt_Else(stmts)
        
        # <--- FUNCTION CALL --->
        elif (node_type == "Expr_FuncCall"):
            name = parsed_ast['name']['parts'][0]
            print(bcolors.OKGREEN + node_type + " -> " + name + bcolors.ENDC)
            args_list = parsed_ast['args']
            args = []
            for arg in args_list:
                args.append(create_nodes(arg, symbol_table, policy))
            
            funcall = Expr_FuncCall(name, args, policy.get_vultype(name))
            
            if funcall.is_sanitizer():
                funcall.sanitizers.append([funcall.get_name()])

            # sources contain sources from unsanitized flows
            # sanitized_sources contain sources from sanitized flows
            for arg in args:
                # function sources: l.u.b. with the arg's
                print("DEBUG ARG: " + str(arg.get_sources()))
                print("DEBUG FUN: " + str(funcall.get_sources()))
                funcall.set_sources(policy.lub(funcall.get_sources(), arg.get_sources()))

                # function sanitizers: union with the arg's
                for sanitizer in arg.get_sanitizers():
                    if funcall.is_sanitizer():
                        sanitizer = [funcall.get_name()] + sanitizer # add funcal name to beginning of list
                    funcall.sanitizers.append(sanitizer)

                # function sanitized sources: l.u.b. with the arg's
                funcall.set_sanitized_sources(policy.lub(funcall.get_sanitized_sources(), arg.get_sanitized_sources()))
                
                # -------------------- #
                
                # sensitive function: add sources and sanitized sources
                if funcall.is_sink():
                    for source in arg.get_sources():  
                        # the arg's (unsanitized) sources are the function's  
                        source_copy = deepcopy(source)
                        policy.get_vulnerability().add_instance(source_copy, funcall.get_name(), True, [])                            
                    
                    for sanitized_source in arg.get_sanitized_sources():
                        # the arg's sanitized sources are the function's
                        sanitized_source_copy = deepcopy(sanitized_source)
                        sanitizers_list_copy = deepcopy(arg.get_sanitizers())
                        policy.get_vulnerability().add_instance(sanitized_source_copy, funcall.get_name(), False, sanitizers_list_copy)
                        print("OUTPUT: " + str(policy.get_vulnerability().output))
            
            # if the function is a sanitizer: all of its sources are  now sanitized
            if funcall.is_sanitizer():
                funcall.add_sanitized_sources(funcall.get_sources())
                funcall.sources = []

            return funcall

        # <--- NAME --->
        elif (node_type == "Name"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Name(parsed_ast['parts'])

        # <--- ARG --->
        elif (node_type == "Arg"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            value = create_nodes(parsed_ast['value'], symbol_table, policy)
            return Arg(value)

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
            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            stmts = create_nodes(parsed_ast['stmts'], symbol_table, policy)
            return Stmt_While(cond, stmts)
        
        else: # discard the node
            return None
        
if __name__== "__main__":
    main(sys.argv, len(sys.argv))