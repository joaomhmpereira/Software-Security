class Symbol_Table:
    def __init__(self) -> None:
        self.variables = []

    def add_variable(self, variable):
        self.variables.append(variable)

    def get_variable(self, var_name):
        for variable in self.variables:
            if variable.name == var_name:
                return variable
        return None
    
    def merge_symbols(self, other, policy):
        result = Symbol_Table()
        
        print("leonor!!!!!!!!!!!!")
        print(self)
        print("leonor!!!!!!!!!!!!")
        print(other)
        for variable in self.variables:
            # check if it's common
            other_variable = other.get_variable(variable.name)
            
            # if it's common ... 
            if other_variable is not None:
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
                    
                    result.add_variable(variable)
                else:
                    # if ours is not tainted, return the other's
                    result.add_variable(other_variable)
            else:
                result.add_variable(variable) 
        
        for other_variable in other.variables:
            variable = result.get_variable(other_variable.name)
            if variable is None:
                result.add_variable(variable)
        
        return result
                
    def __str__(self):
        s = "< "
        for var in self.variables:
            s += str(var) + " | "
        return s + ">"