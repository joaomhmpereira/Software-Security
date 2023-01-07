import sys, json
from AST.stmt_expr import Stmt_Expression
from AST.expr_assign import Expr_Assign
from AST.expr_variable import Expr_Variable
from AST.expr_const_fetch import Expr_Const_Fetch
from AST.stmt_if import Stmt_If
from AST.stmt_else import Stmt_Else
from AST.stmt_elseif import Stmt_ElseIf
from AST.stmt_switch import Stmt_Switch
from AST.stmt_case import Stmt_Case
from AST.stmt_nop import Stmt_Nop
from AST.stmt_while import Stmt_While
from AST.stmt_for import Stmt_For
from AST.stmt_break import Stmt_Break
from AST.name import Name
from AST.arg import Arg
from AST.expr_funccall import Expr_FuncCall
from AST.symbol_table import Symbol_Table
from AST.binopexpr import Binop_Expr
from AST.implicit_checker import Implicit_Checker
from AST.expr_not import Expr_Not
from AST.inc_dec import Inc_Dec
from AST.expr_array_dim_fetch import Expr_Array_Dim_Fetch
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
        print(bcolors.FAIL + "Usage: python php-analyser.py <code_slice>.json <vuln_patter>.json" + bcolors.ENDC)
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
    output_file = 'output/' + B[0] + '.output.json'
    
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
        print(bcolors.OKBLUE + "POLICY: " + bcolors.ENDC + str(policy))
        # create the AST nodes for the corresponding json
        symbol_table = Symbol_Table()

        # create implicit checker
        if policy.get_vulnerability().is_implicit():
            implicit_checker = Implicit_Checker()
        else:
            implicit_checker = None

        create_nodes(parsed_ast, symbol_table, policy, implicit_checker)
        output += policy.get_vulnerability().output
    
    with open(output_file, 'w') as outfile:
        json.dump(output, outfile, ensure_ascii=False, indent=4)
        
def create_nodes(parsed_ast, symbol_table=None, policy=None, implicit_checker=None):
    """
    Given a json, parse it and create the corresponding AST nodes
    """

    if (type(parsed_ast) == list):  # if we receive a list of instructions (list of dictionaries)
        instructions = []
        for instruction in parsed_ast:
            instructions.append(create_nodes(instruction, symbol_table, policy, implicit_checker)) #create the nodes for each instruction

        for instruction in instructions:
            print(bcolors.HEADER + "Instruction: " +  bcolors.ENDC + str(instruction))
        return instructions

    elif (type(parsed_ast) == dict):    # if we receive a single instruction
        # get the type of the node we're analyzing
        node_type = parsed_ast['nodeType']

        # <--- EXPRESSION --->
        if (node_type == "Stmt_Expression"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(create_nodes(parsed_ast['expr'], symbol_table, policy, implicit_checker))
        
        # <--- ASSIGNMENT --->
        elif ("Expr_Assign" in node_type):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            rval = create_nodes(parsed_ast['expr'], symbol_table, policy, implicit_checker)
            lval = create_nodes(parsed_ast['var'], symbol_table, policy, implicit_checker)
            
            if (node_type == "Expr_Assign"):
                # initialized variables: remove from source
                if not lval.is_source():
                    lval.del_source(lval.name)
             
            sources = policy.lub(deepcopy(lval.get_sources()), deepcopy(rval.get_sources()))
            sanitized_sources = policy.lub(deepcopy(lval.get_sanitized_sources()), deepcopy(rval.get_sanitized_sources()))
            for sanitizer in rval.get_sanitizers():
                lval.add_sanitizer(sanitizer)
                    
            # add implicit sources, sanitized sources and sanitizers to variable
            if policy.get_vulnerability().is_implicit():
                sources = policy.lub(sources, deepcopy(implicit_checker.get_flat_sources()))
                sanitized_sources = policy.lub(sanitized_sources, deepcopy(implicit_checker.get_flat_sanitized_sources()))
                for implicit_sanitizer in implicit_checker.get_flat_sanitizers():
                    lval.add_sanitizer(implicit_sanitizer)

            lval.set_sources(sources)
            print("SOURCES: " + str(lval.get_sources()))
            
            lval.set_sanitized_sources(sanitized_sources)
            print("SANITIZED SOURCES: " + str(sanitized_sources))

            # explicit leaks
            if lval.is_sink():
                if policy.get_vulnerability().is_implicit():    # output implicit vulnerabilities
                    for implicit_source in implicit_checker.get_flat_sources():
                        policy.get_vulnerability().add_instance(implicit_source, lval.get_name(), True, [])
                    
                    for implicit_sanitized_source in implicit_checker.get_flat_sanitized_sources():
                        implicit_sanitizers_list_copy = deepcopy(implicit_checker.get_flat_sanitizers())
                        policy.get_vulnerability().add_instance(implicit_sanitized_source, lval.get_name(), False, implicit_sanitizers_list_copy)
                        
                for source in policy.lub(rval.get_sources(), lval.get_sources()):
                    source_copy = deepcopy(source)
                    policy.get_vulnerability().add_instance(source_copy, lval.get_name(), True, [])                            
                
                for sanitized_source in rval.get_sanitized_sources():
                    sanitized_source_copy = deepcopy(sanitized_source)
                    sanitizers_list_copy = deepcopy(rval.get_sanitizers())
                    policy.get_vulnerability().add_instance(sanitized_source_copy, lval.get_name(), False, sanitizers_list_copy)

            return Expr_Assign(lval, rval)
        
        # <--- VARIABLE --->
        elif (node_type == "Expr_Variable"):
            name = "$" + parsed_ast['name']
            print(bcolors.OKGREEN + node_type + " -> " + name + bcolors.ENDC)
            variable = symbol_table.get_variable(name)
            
            if variable is None:
                print('variable is not in symtable')
                variable = Expr_Variable(name, policy.get_vultype(name))
                symbol_table.add_variable(variable)
            return variable
        
        # <--- BINARY EXPRESSIONS --->
        elif ("Expr_BinaryOp" in node_type):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            left = create_nodes(parsed_ast['left'], symbol_table, policy, implicit_checker)
            right = create_nodes(parsed_ast['right'], symbol_table, policy, implicit_checker)
            expr = Binop_Expr(left, right)
            
            expr.set_sources(policy.lub(left.get_sources(), right.get_sources()))
            expr.set_sanitized_sources(policy.lub(left.get_sanitized_sources(), right.get_sanitized_sources()))
            sanitizers = []
            for sanitizer in left.get_sanitizers() + right.get_sanitizers():
                if sanitizer not in sanitizers:
                    sanitizers.append(sanitizer)        
            expr.set_sanitizers(sanitizers)
            return expr

        # <--- SCALARS  --->
        elif ("Scalar_" in node_type):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Stmt_Expression(parsed_ast['value'])
        
        # <--- IF --->
        elif (node_type == "Stmt_If"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            
            # push context into implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.push_source(cond.get_sources())
                implicit_checker.push_sanitizer(cond.get_sanitizers())
                implicit_checker.push_sanitized_source(cond.get_sanitized_sources())

            symbol_table_if = deepcopy(symbol_table)
            symbol_table_else = deepcopy(symbol_table)
            symbol_table_initial = deepcopy(symbol_table)
                        
            stmts = create_nodes(parsed_ast['stmts'], symbol_table_if, policy, implicit_checker)
            else_clause = create_nodes(parsed_ast['else'], symbol_table_else, policy, implicit_checker)
            
            merged_symbol_table, common_variables = symbol_table_if.merge_symbols(symbol_table_else, policy)

            symbol_table.add_missing_variables(merged_symbol_table, common_variables)

            
            # elseifs 
            elseif_list = parsed_ast['elseifs']
            elseifs = []
            for elseif in elseif_list:
                symbol_table_elseif = deepcopy(symbol_table_initial)
                elseifs.append(create_nodes(elseif, symbol_table_elseif, policy, implicit_checker))

                # propagate changed symbol table
                merged_symbol_table, common_variables = symbol_table_elseif.merge_symbols(symbol_table, policy)
                symbol_table.add_missing_variables(merged_symbol_table, common_variables)


            # pop context out of implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.pop_source()
                implicit_checker.pop_sanitizer()
                implicit_checker.pop_sanitized_source()

            return Stmt_If(cond, stmts, elseifs, else_clause)

        # <--- STMT ELSE --->
        elif (node_type == "Stmt_Else"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            stmts = create_nodes(parsed_ast['stmts'], symbol_table, policy, implicit_checker)
            return Stmt_Else(stmts)

        # <--- STMT ELSEIF OR CASE--->
        elif (node_type == "Stmt_ElseIf") or (node_type == "Stmt_Case"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)

            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            
            # push context into implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.push_source(cond.get_sources())
                implicit_checker.push_sanitizer(cond.get_sanitizers())
                implicit_checker.push_sanitized_source(cond.get_sanitized_sources())

            symbol_table_stmts = deepcopy(symbol_table)

            stmts = create_nodes(parsed_ast['stmts'], symbol_table_stmts, policy, implicit_checker)

            symbol_table.add_missing_variables(symbol_table_stmts, symbol_table_stmts.get_variables())

            # pop context out of implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.pop_source()
                implicit_checker.pop_sanitizer()
                implicit_checker.pop_sanitized_source()

            if node_type == "Stmt_Case":
                return Stmt_Case(cond, stmts)
            else:
                return Stmt_ElseIf(cond, stmts)

        # <--- FUNCTION CALL, ECHO  --->
        elif (node_type == "Expr_FuncCall") or (node_type == "Stmt_Echo"):

            if (node_type == "Expr_FuncCall"):
                name = parsed_ast['name']['parts'][0]
                args_list = parsed_ast['args']
            else:
                name = "echo"
                args_list = parsed_ast['exprs']
            
            print(bcolors.OKGREEN + node_type + " -> " + name + bcolors.ENDC)

            args = []
            for arg in args_list:
                args.append(create_nodes(arg, symbol_table, policy, implicit_checker))
            
            funcall = Expr_FuncCall(name, args, policy.get_vultype(name))
            
            if funcall.is_sanitizer():
                funcall.add_sanitizer([funcall.get_name()])

            if policy.get_vulnerability().is_implicit():
                sources = policy.lub(deepcopy(funcall.get_sources()), deepcopy(implicit_checker.get_flat_sources()))
                sanitized_sources = policy.lub(deepcopy(funcall.get_sanitized_sources()), deepcopy(implicit_checker.get_flat_sanitized_sources()))
                for implicit_sanitizer in implicit_checker.get_flat_sanitizers():
                    funcall.add_sanitizer(implicit_sanitizer)

            # sources contain sources from unsanitized flows
            # sanitized_sources contain sources from sanitized flows
            for arg in args:
                # function sources: l.u.b. with the arg's
                if policy.get_vulnerability().is_implicit():
                    sources = policy.lub(sources, deepcopy(arg.get_sources()))
                    sanitized_sources = policy.lub(sanitized_sources, deepcopy(arg.get_sanitized_sources()))
                else:
                    sources = policy.lub(deepcopy(funcall.get_sources()), deepcopy(arg.get_sources()))
                    sanitized_sources = policy.lub(deepcopy(funcall.get_sanitized_sources()), deepcopy(arg.get_sanitized_sources()))

                # function sanitizers: union with the arg's
                for sanitizer in arg.get_sanitizers():
                    if funcall.is_sanitizer() and sanitizer not in funcall.get_sanitizers():
                        sanitizer = [funcall.get_name()] + sanitizer # add funcal name to beginning of list
                    funcall.add_sanitizer(sanitizer)

                # function sanitized sources: l.u.b. with the arg's
                funcall.set_sanitized_sources(sanitized_sources)
                funcall.set_sources(sources)
                
                # -------------------- #
                
                # explicit leaks
                # sensitive function: add sources and sanitized sources
                if funcall.is_sink():
                    for source in arg.get_sources():  
                        # the arg's (unsanitized) sources are the function's  
                        policy.get_vulnerability().add_instance(source, funcall.get_name(), True, [])                            
                    
                    for sanitized_source in arg.get_sanitized_sources():
                        # the arg's sanitized sources are the function's
                        sanitizers_list_copy = deepcopy(arg.get_sanitizers())
                        policy.get_vulnerability().add_instance(sanitized_source, funcall.get_name(), False, sanitizers_list_copy)
            
            # if the function is a sanitizer: all of its sources are  now sanitized
            if funcall.is_sanitizer():
                funcall.add_sanitized_sources(funcall.get_sources())
                funcall.sources = []
            
            # implicit leaks
            if funcall.is_sink():
                if policy.get_vulnerability().is_implicit():
                    for implicit_source in implicit_checker.get_flat_sources():
                        policy.get_vulnerability().add_instance(implicit_source, funcall.get_name(), True, [])
                    for implicit_sanitized_source in implicit_checker.get_flat_sanitized_sources():
                        implicit_sanitized_source_copy = deepcopy(implicit_sanitized_source)
                        policy.get_vulnerability().add_instance(implicit_sanitized_source, funcall.get_name(), False, implicit_sanitized_source_copy)

            return funcall

        # <--- STMT SWITCH --->
        elif (node_type == "Stmt_Switch"):

            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            
            # push context into implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.push_source(cond.get_sources())
                implicit_checker.push_sanitizer(cond.get_sanitizers())
                implicit_checker.push_sanitized_source(cond.get_sanitized_sources())

            symbol_table_switch = deepcopy(symbol_table)

            cases = create_nodes(parsed_ast['cases'], symbol_table_switch, policy, implicit_checker)

            symbol_table.add_missing_variables(symbol_table_switch, symbol_table_switch.get_variables())

            # pop context out of implicit_checker stacks
            if policy.get_vulnerability().is_implicit():
                implicit_checker.pop_source()
                implicit_checker.pop_sanitizer()
                implicit_checker.pop_sanitized_source()

            return Stmt_Switch(cond, cases)

        # <--- STMT CASE --->
        elif (node_type == "Stmt_Case"):
            cond = create_nodes(parsed_ast['cond'], symbol_table, policy)
            stmts = create_nodes(parsed_ast['stmts']), symbol_table, policy
            return Stmt_Case(cond, stmts)

        # <--- NAME --->
        elif (node_type == "Name"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            return Name(parsed_ast['parts'])

        # <--- ARG --->
        elif (node_type == "Arg"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            value = create_nodes(parsed_ast['value'], symbol_table, policy, implicit_checker)
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

            symtable_body = deepcopy(symbol_table)
            
            #Special case when vulnerabilities are only detected with multiple body loop iterations
            last_symtable = None
            while True:
                condition = create_nodes(parsed_ast['cond'], symtable_body, policy, implicit_checker)

                if policy.get_vulnerability().is_implicit():
                    implicit_checker.push_source(condition.get_sources())
                    implicit_checker.push_sanitizer(condition.get_sanitizers())
                    implicit_checker.push_sanitized_source(condition.get_sanitized_sources())

                stmts = create_nodes(parsed_ast['stmts'], symtable_body, policy, implicit_checker)

                if last_symtable is not None:
                    oldLastSymtable = deepcopy(last_symtable)
                    last_symtable, _ = last_symtable.merge_symbols(symtable_body, policy)
                    if oldLastSymtable == last_symtable:
                        # pop context out of implicit_checker stacks
                        if policy.get_vulnerability().is_implicit():
                            implicit_checker.pop_source()
                            implicit_checker.pop_sanitizer()
                            implicit_checker.pop_sanitized_source()
                            print(implicit_checker)
                        break
                else:
                    last_symtable = deepcopy(symtable_body)
                
                # pop context out of implicit_checker stacks
                if policy.get_vulnerability().is_implicit():
                    implicit_checker.pop_source()
                    implicit_checker.pop_sanitizer()
                    implicit_checker.pop_sanitized_source()

            symbol_table.add_missing_variables(last_symtable, last_symtable.get_variables())

            return Stmt_While(condition, stmts)

        # <--- FOR --->
        elif (node_type == "Stmt_For"):
            init = create_nodes(parsed_ast['init'], symbol_table, policy, implicit_checker)
            
            symtable_body = deepcopy(symbol_table)
            last_symtable = None
            while True:
                sources, sanitizers, sanitized_sources = [], [], []
                conditions = []
                conds = parsed_ast['cond']
                for cond in conds:
                    condition = create_nodes(cond, symtable_body, policy, implicit_checker)
                    conditions.append(condition)

                    # gather sources, sanitizers and sanitized sources
                    if policy.get_vulnerability().is_implicit():
                        # sources
                        sources = policy.lub(sources, condition.get_sources())
                        # sanitized_sources
                        sanitized_sources = policy.lub(sanitized_sources, condition.get_sanitized_sources())
                        # sanitizers
                        for sanitizer in condition.get_sanitizers():
                            if sanitizer not in sanitizers:
                                sanitizers.append(sanitizer)

                # push context into implicit_checker stack
                if policy.get_vulnerability().is_implicit():
                    implicit_checker.push_source(sources)
                    implicit_checker.push_sanitizer(sanitizers)
                    implicit_checker.push_sanitized_source(sanitized_sources)
                
                stmts = create_nodes(parsed_ast['stmts'], symtable_body, policy, implicit_checker)
                loop = create_nodes(parsed_ast['loop'], symtable_body, policy, implicit_checker)

                if last_symtable is not None:
                    oldLastSymtable = deepcopy(last_symtable)
                    last_symtable, _ = last_symtable.merge_symbols(symtable_body, policy)
                    if oldLastSymtable == last_symtable:
                        # pop context out of implicit_checker stacks
                        if policy.get_vulnerability().is_implicit():
                            implicit_checker.pop_source()
                            implicit_checker.pop_sanitizer()
                            implicit_checker.pop_sanitized_source()
                        break
                else:
                    last_symtable = deepcopy(symtable_body)
            
            symbol_table.add_missing_variables(last_symtable, last_symtable.get_variables())
            return Stmt_For(init, conditions, loop, stmts)
   
        # <--- CONST FETCH --->
        elif (node_type == "Expr_ConstFetch"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            name = create_nodes(parsed_ast['name'], symbol_table, policy, implicit_checker)
            return Expr_Const_Fetch(name)
        
        # <--- BITWISE/BOOLEAN NOT --->
        elif (node_type == "Expr_BitwiseNot") or (node_type == "Expr_BooleanNot"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            expr = create_nodes(parsed_ast['expr'], symbol_table, policy, implicit_checker)
            return Expr_Not(expr)
        
        # <--- POST/PRE-DEC/INC --->
        elif (node_type == "Expr_PostInc") or (node_type == "Expr_PostDec") or (node_type == "Expr_PreDec") or (node_type == "Expr_PreInc"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            var = create_nodes(parsed_ast['var'], symbol_table, policy, implicit_checker)
            
            return Inc_Dec(var)

        # <--- ARRAYDIMFETCH --->
        elif (node_type == "Expr_ArrayDimFetch"):
            print(bcolors.OKGREEN + node_type + bcolors.ENDC)
            var = create_nodes(parsed_ast['var'], symbol_table, policy, implicit_checker)
            dim = create_nodes(parsed_ast['dim'], symbol_table, policy, implicit_checker)
            return Expr_Array_Dim_Fetch(var, dim)

        #  <--- CONTINUE, COMMENTS, ... EVERYTHING ELSE --->
        else: # discard the node
            return None
        
if __name__== "__main__":
    main(sys.argv, len(sys.argv))