from AST.expression import Expression

class Expr_Not(Expression):
    def __init__(self, expr):
        super().__init__()
        self.expr = expr
        self.set_sources(self.expr.get_sources())
        self.set_sanitizers(self.expr.get_sanitizers())
        self.set_sanitized_sources(self.expr.get_sanitized_sources())

    def __str__(self):
        return 'Not(Expr: {}, ASources: {}, ASanitizers: {}, ASanSources: {})'.format(self.expr, self.get_sources(), self.get_sanitizers(), self.get_sanitized_sources())    