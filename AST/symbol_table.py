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
    
    def merge_symbols(self, other_symbol_table, policy) -> list:
        """
        Given two symbol tables merge them and return the resulting symbol table
        and a list containing vairiables that are in both input symbol tables
        """
        symtable_to_return = Symbol_Table()
        common_variables = []
        for variable in self.variables:
            # check if it's common
            other_variable = other_symbol_table.get_variable(variable.get_name())
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
                    symtable_to_return.add_variable(other_variable)
                    common_variables.append(other_variable)
            else:
                # if only our symbol table has it
                symtable_to_return.add_variable(variable) 
                
        # variables only in other: add to symtable
        for other_variable in other_symbol_table.get_variables():
            variable = symtable_to_return.get_variable(other_variable.get_name())
            if variable is None:
                symtable_to_return.add_variable(other_variable)
        
        return [symtable_to_return, common_variables]
    
    def add_missing_variables(self, other_symbol_table, common_list):
        """
        Add to a symbol table all variables that are not already on it
        If a variable is not in the common list it means that it was only initialized in one of the branches
        add it as its own source
        """
        for variable in other_symbol_table.get_variables():
            # variables that are not on the common list have not been initialized in self.symtable
            # so we'll treat them as sources
            if variable not in common_list:  
                variable.add_source(variable.get_name())
                common_list.append(variable)
        self.variables = common_list
                
    def __repr__(self):
        s = "[ "
        for var in self.variables:
            s += str(var) + " | "
        return s[:-2] + "]"

    def __eq__(self, other_symbol_table) -> bool:
        """
        Method for comparing two symbol tables
        """
        if self.__class__ == other_symbol_table.__class__:  # check if they're both from the Symbol_Table class
            if len(self.variables) != len(other_symbol_table.get_variables()):  # check if they both have the same length
                return False
            for var in self.variables:  # if they have same length, compare the variables
                other_var = other_symbol_table.get_variable(var.get_name())
                if var.get_sources() != other_var.get_sources() or var.get_sanitizers() != other_var.get_sanitizers() or var.get_sanitized_sources() != other_var.get_sanitized_sources():
                    return False
            return True
        else:
            return False