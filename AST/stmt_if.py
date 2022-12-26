class Stmt_If:
    def __init__(self, cond, stmts, elseifs, else_clause) -> None:
        self.cond = cond
        self.stms = stmts
        self.elseifs = elseifs
        self.else_clause = else_clause

    def __str__(self) -> str:
        return 'Stmt_If(Condition: {}, Statements: {}, ElseIfs: {}, Else: {})'.format(self.cond, self.stms, self.elseifs, self.else_clause)