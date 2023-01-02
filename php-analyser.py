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
from AST.arg import Arg
from AST.expr_funccall import Expr_FuncCall
from AST.symbol_table import Symbol_Table
from AST.symbol_stack import Symbol_Stack
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
    
    output = [] 
    for policy in policies:
        print(policy)
        symbol_table = Symbol_Table()
        # create the AST nodes for the corresponding json
        create_nodes(parsed_ast, symbol_table, Symbol_Stack(symbol_table), policy)
        output += policy.get_vulnerability().output

    """
    ter lista de possiveis symtable flows,
    depois de correr uma vez, voltar a correr novamente com cada uma das symtables
    nao da porque a ordem pela qual as coisas acontecem importa
    """
    
    with open(output_file, 'w') as outfile:
        json.dump(output, outfile, ensure_ascii=False, indent=4)
        
def create_nodes(parsed_ast, symbol_table=None, symbol_stack=None, policy=None):
    """
    Given a json, parse it and create the corresponding AST nodes
    """
    #print s
    #if not isinstance(symbol_stack.get_tail(), list):
    #    symbol_table = symbol_table.merge_symbols(symbol_stack.get_tail(), policy)

    """
    AQUI TEMOS TIPO UMA LISTA DE SYMTABLES E VAMOS FAZER UMA EXECUÇÃO COM CADA SYMTABLE
    """
    #print(bcolors.WARNING + "********** PARSED AST **********" + bcolors.ENDC)
    #print(parsed_ast)
    #print(bcolors.WARNING + "********************************" + bcolors.ENDC)

    if symbol_table:
        print(bcolors.OKCYAN + "=======")
        print(symbol_table)
        print("=======" + bcolors.ENDC)
    

    #print(bcolors.OKBLUE + "Inside create_nodes" + bcolors.ENDC)
    if (type(parsed_ast) == list):  # if we receive a list of instructions (list of dictionaries)
        #print(bcolors.OKCYAN + "parsed_ast is a list" + bcolors.ENDC)
        instructions = []
        for instruction in parsed_ast:
            instructions.append(create_nodes(instruction, symbol_table, symbol_stack, policy)) #create the nodes for each instruction

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
            return Stmt_Expression(create_nodes(parsed_ast['expr'], symbol_table, symbol_stack, policy))
        
        # <--- ASSIGNMENT --->
        elif (node_type == "Expr_Assign"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            rval = create_nodes(parsed_ast['expr'], symbol_table, symbol_stack, policy)
            lval = create_nodes(parsed_ast['var'], symbol_table, symbol_stack, policy)
            
            # initialized variables: remove from source
            if not lval.is_source():
                lval.del_source(lval.name)

            print(bcolors.WARNING + str(rval) + bcolors.ENDC)
             
            sources = policy.lub(lval.get_sources(), rval.get_sources())

            sanitized_sources = policy.lub(lval.get_sanitized_sources(), rval.get_sanitized_sources())
            lval.set_sources(sources)

            for sanitizer in rval.get_sanitizers():
                if sanitizer not in lval.sanitizers:
                    lval.sanitizers.append(sanitizer)

            lval.set_sanitized_sources(sanitized_sources)
            
            # explicit leaks
            if isinstance(rval, Expr_FuncCall) or isinstance(rval, Expr_Variable):
                if lval.is_sink():
                    for source in rval.get_sources():
                        print(bcolors.HEADER + "Outputing vuln without san flows" + bcolors.ENDC)
                        source_copy = deepcopy(source)
                        name_copy = deepcopy(lval.name)
                        policy.get_vulnerability().add_instance(source_copy, name_copy, True, [])                            
                    
                    for sanitized_source in rval.get_sanitized_sources():
                        print(bcolors.HEADER + "Outputing vuln witho san flows" + bcolors.ENDC)
                        print(bcolors.WARNING + "SANITIZERS ASSIGNMENT: " + str(rval.get_sanitizers()) + bcolors.ENDC)
                        sanitized_source_copy = deepcopy(sanitized_source)
                        name_copy = deepcopy(lval.name)
                        sanitizers_list_copy = deepcopy(rval.get_sanitizers())
                        policy.get_vulnerability().add_instance(sanitized_source_copy, name_copy, False, sanitizers_list_copy)

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

        # <--- EXP BINARY GREATER --->
        elif (node_type == "Expr_BinaryOp_Greater"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Greater(left, right)
        
        # <--- EXP BINARY SMALLER --->
        elif (node_type == "Expr_BinaryOp_Smaller"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Smaller(left, right)
        
        # <--- EXP BINARY EQUAL --->
        elif (node_type == "Expr_BinaryOp_Equal"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Equal(left, right)

        # <--- EXP BINARY NOT EQUAL --->
        elif (node_type == "Expr_BinaryOp_NotEqual"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Not_Equal(left, right)

        # <--- EXP BINARY PLUS --->
        elif (node_type == "Expr_BinaryOp_Plus"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Plus(left, right)

        # <--- EXP BINARY CONCAT --->
        elif (node_type == "Expr_BinaryOp_Concat"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, symbol_stack, policy)
            right = create_nodes(parsed_ast['right'], symbol_table, symbol_stack, policy)
            return BExpr_Concat(left, right)

        # <--- SCALAR LNUMBER --->
        elif (node_type == "Scalar_LNumber"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['value'])

        # <--- IF --->
        elif (node_type == "Stmt_If"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            print("======== BEGIN ========")
            print(bcolors.FAIL + str(symbol_table) + bcolors.ENDC)
            print("=======================")
            cond = create_nodes(parsed_ast['cond'], symbol_table, symbol_stack, policy)
            
            symbol_table_if = deepcopy(symbol_table)
            symbol_table_else = deepcopy(symbol_table)
            
            # join all symtables and push to symstack
            element = [symbol_table_if, symbol_table_else]
            # if len(symbol_table_elseifs) > 0:
            #     element.extend(symbol_table_elseifs)
            symbol_stack.push(element)
            
            print("Symbol stack::::" + str(symbol_stack))
            
            stmts = create_nodes(parsed_ast['stmts'], symbol_table_if, symbol_stack, policy)

            print(bcolors.OKBLUE + "SYMBOL TABLEEEEE" + str(symbol_table) + bcolors.ENDC)

            if parsed_ast['else'] is not None:
                else_clause = create_nodes(parsed_ast['else'], symbol_table_else, symbol_stack, policy)

                print(bcolors.HEADER + str(stmts) + bcolors.ENDC)
                elseif_list = parsed_ast['elseifs']
                elseifs = []
                symbol_table_elseifs = []
                for elseif in elseif_list:
                    symbol_table_elseif = deepcopy(symbol_table)
                    elseifs.append(create_nodes(elseif, symbol_table_elseif, symbol_stack, policy))
                    symbol_table_elseifs.append(symbol_table_elseif)
                
                print(bcolors.WARNING + "IF symtable " + str(symbol_table_if) + bcolors.ENDC)
                print(bcolors.WARNING + "ELSE symtable " + str(symbol_table_else) + bcolors.ENDC)
                
                last = symbol_stack.pop()
                last_merged = Symbol_Table()
                for el in last:
                    last_merged = last_merged.merge_symbols(el, policy)
                print("LAST MERGED::::" + str(last_merged))
                
                tail = symbol_stack.get_tail()
                if isinstance(tail, list):
                    tail[-1] = tail[-1].merge_symbols(last_merged, policy)
                else:
                    tail = tail.merge_symbols(last_merged, policy)
                
                symbol_stack.pop()
                symbol_stack.push(tail)
                
                symbol_table = tail
                
                print("RESULT::::::" + str(symbol_stack))
                                
                print("======== END ========")
                print(bcolors.FAIL + str(symbol_table) + bcolors.ENDC)
                print("=======================")
                
                return Stmt_If(cond, stmts, elseifs, else_clause)
            else:
                # TODO
                pass

        # <--- STMT ELSE --->
        elif (node_type == "Stmt_Else"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            stmts = create_nodes(parsed_ast['stmts'], symbol_table, symbol_stack, policy)
            return Stmt_Else(stmts)
        
        #0x7f42960950f0
        # <--- FUNCTION CALL --->
        elif (node_type == "Expr_FuncCall"):
            name = parsed_ast['name']['parts'][0]
            print(bcolors.OKGREEN + node_type + " -> " + name + bcolors.ENDC)
            args_list = parsed_ast['args']
            args = []
            for arg in args_list:
                args.append(create_nodes(arg, symbol_table, symbol_stack, policy))
            
            funcall = Expr_FuncCall(name, args, policy.get_vultype(name))
            
            if funcall.is_sanitizer():
                funcall.sanitizers.append([funcall.get_name()])

            """
            sources contain sources from unsanitized flows
            sanitized_sources contain sources from sanitized flows
            """
            for arg in args:
                print(bcolors.FAIL + "Arg: " + str(arg) + bcolors.ENDC)
                print(bcolors.OKBLUE + "Funccal: " + str(funcall) + bcolors.ENDC)
                funcall.set_sources(policy.lub(funcall.get_sources(), arg.get_sources()))

                for sanitizer in arg.get_sanitizers():
                    if funcall.is_sanitizer():
                        sanitizer = [funcall.get_name()] + sanitizer # add funcal name to beginning of list
                    funcall.sanitizers.append(sanitizer)

                funcall.set_sanitized_sources(policy.lub(funcall.get_sanitized_sources(), arg.get_sanitized_sources()))
                if funcall.is_sink():
                    for source in arg.get_sources():    
                        print(bcolors.HEADER + "Outputing vuln without san flows" + bcolors.ENDC)
                        source_copy = deepcopy(source)
                        funcall_name_copy = deepcopy(funcall.name)
                        policy.get_vulnerability().add_instance(source_copy, funcall_name_copy, True, [])                            
                    
                    for sanitized_source in arg.get_sanitized_sources():
                        print(bcolors.HEADER + "Outputing vuln with san flows" + bcolors.ENDC)
                        print(bcolors.WARNING + "SANITIZERS FCALL: " + str(arg.get_sanitizers()) + bcolors.ENDC)
                        sanitized_source_copy = deepcopy(sanitized_source)
                        funcall_name_copy = deepcopy(funcall.name)
                        sanitizers_list_copy = deepcopy(arg.get_sanitizers())
                        policy.get_vulnerability().add_instance(sanitized_source_copy, funcall_name_copy, False, sanitizers_list_copy)

            if funcall.is_sanitizer():
                #for arg in args:
                    #print(bcolors.OKGREEN + str(arg) + bcolors.ENDC)
                    #arg.add_sanitized_sources(funcall.get_sanitizers())
                    #if isinstance(arg.value, Expr_Variable) or isinstance(arg.value, Expr_FuncCall):
                        #print(arg.value.name)
                        #funcall.add_sanitized_sources([arg.value.get_name()])
                funcall.add_sanitized_sources(funcall.get_sources())
                funcall.sources = []    # limpar as sources, todas as sources foram sanitized
                print(bcolors.FAIL + "san sources" + str(funcall.get_sanitized_sources()) + bcolors.ENDC)
                print(bcolors.FAIL + "unsan sources: " + str(funcall.get_sources()) + bcolors.ENDC)

            return funcall

        # <--- NAME --->
        elif (node_type == "Name"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Name(parsed_ast['parts'])

        # <--- ARG --->
        elif (node_type == "Arg"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            value = create_nodes(parsed_ast['value'], symbol_table, symbol_stack, policy)
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
            cond = create_nodes(parsed_ast['cond'], symbol_table, symbol_stack, policy)
            stmts = create_nodes(parsed_ast['stmts'], symbol_table, symbol_stack, policy)
            return Stmt_While(cond, stmts)
        
        else: # discard the node
            return None
        
if __name__== "__main__":
    main(sys.argv, len(sys.argv))
    
    