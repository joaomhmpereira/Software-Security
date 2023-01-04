from AST.expression import Expression

class Inc_Dec(Expression):
    def __init__(self, var) -> None:
        super().__init__()
        self.var = var
        self.set_sources(self.var.get_sources())
        self.set_sanitizers(self.var.get_sanitizers())
        self.set_sanitized_sources(self.var.get_sanitized_sources())

    def __repr__(self) -> str:
        return 'Inc_Dec(Var: {}, ASources: {}, ASanitizers: {}, ASanSources: {})'.format(self.var, self.get_sources(), self.get_sanitizers(), self.get_sanitized_sources())