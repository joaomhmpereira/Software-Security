class Stmt_ElseIf:
    def __init__(self, cond, stmts) -> None:
        self.cond = cond
        self.stms = stmts

    def __str__(self) -> str:
        return 'Stmt_ElseIf(Condition: {}, Statements: {})'.format(self.cond, self.stms)