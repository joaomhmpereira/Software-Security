class Symbol_Table:
    def __init__(self) -> None:
        self.variables = []

    def addVariable(self, variable):
        self.variables.append(variable)

    def getVariable(self, var_name):
        for variable in self.variables:
            if variable.name == var_name:
                return variable
        return None
    
    def __str__(self):
        s = "< "
        for var in self.variables:
            s += str(var) + ", "
        return s + ">"