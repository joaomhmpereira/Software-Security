class Stmt_Expression:
    def __init__(self, expr) -> None:
        self.expr = expr

    def __str__(self) -> str:
        return 'Stmt_Expression({})'.format(self.expr)