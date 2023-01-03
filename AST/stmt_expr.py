from AST.expression import Expression

class Stmt_Expression(Expression):
    def __init__(self, expr) -> None:
        super().__init__()
        self.expr = expr

    def __repr__(self) -> str:
        return 'Stmt_Expression({})'.format(self.expr)