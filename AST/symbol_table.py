class Symbol_Table:
    def __init__(self) -> None:
        self.variables = []

    def add_variable(self, variable) -> None:
        self.variables.append(variable)

    def get_variables(self) -> list:
        return self.variables

    def get_variable(self, var_name):
        for variable in self.variables:
            if variable.name == var_name:
                return variable
        return None
    
    def merge_symbols(self, other, policy) -> list:
        symtable_to_return = Symbol_Table()
        common_variables = []
        for variable in self.variables:
            # check if it's common
            other_variable = other.get_variable(variable.name)
            if other_variable is not None: # it's common...
                if variable.is_tainted():
                    if other_variable.is_tainted():
                        # if it's tainted in both -> merge
                        variable.set_sources(policy.lub(variable.get_sources(), other_variable.get_sources()))
                        variable.set_sanitized_sources(policy.lub(variable.get_sanitized_sources(), other_variable.get_sanitized_sources()))
                        sanitizers = []
                        for sanitizer in variable.get_sanitizers() + other_variable.get_sanitizers():
                            if sanitizer not in sanitizers:
                                sanitizers.append(sanitizer)
                        variable.set_sanitizers(sanitizers)
                    
                    symtable_to_return.add_variable(variable)
                    common_variables.append(variable)
                else:
                    # if ours is not tainted, return the other's
                    symtable_to_return.add_variable(variable)
                    common_variables.append(variable)
            else:
                # if only our symbol table has it
                symtable_to_return.add_variable(variable) 
                
        # variables only in other: add to symtable
        for other_variable in other.variables:
            variable = symtable_to_return.get_variable(other_variable.get_name())
            if variable is None:
                symtable_to_return.add_variable(other_variable)
        
        return [symtable_to_return, common_variables]
    
    def add_missing_variables(self, other_sym, commonList):
        for variable in other_sym.variables:
            # variables that are not on the common list have not been initialized in self.symtable
            # so we'll treat them as sources
            if variable not in commonList:  
                variable.add_source(variable.get_name())
                commonList.append(variable)
        self.variables = commonList
                
    def __repr__(self):
        s = "< "
        for var in self.variables:
            s += str(var) + " | "
        return s + ">"