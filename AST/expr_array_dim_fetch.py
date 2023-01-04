from AST.expression import Expression

class Expr_Array_Dim_Fetch(Expression):
    def __init__(self, var, dim) -> None:
        super().__init__()
        self.var = var
        self.dim = dim
        
        self.set_sources(list(set(self.var.get_sources()) | set(self.dim.get_sources())))
        self.set_sanitized_sources(list(set(self.var.get_sanitized_sources()) | set(self.dim.get_sanitized_sources()))) 
        for sanitizer in self.var.get_sanitizers() + self.dim.get_sanitizers():
            self.add_sanitizer(sanitizer)
        
    def __repr__(self) -> str:
        return 'ArrayDimFetch(Var: {}, Dim: {}, ASources: {}, ASanitizers: {}, ASanSources: {})'.format(self.var, self.dim, self.get_sources(), self.get_sanitizers(), self.get_sanitized_sources())