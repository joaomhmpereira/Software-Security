class Stmt_While:
    def __init__(self, cond, stmts) -> None:
        self.cond = cond
        self.stms = stmts

    def __str__(self) -> str:
        return 'Stmt_If(Condition: {}, Statements: {})'.format(self.cond, self.stms)