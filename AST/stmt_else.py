class Stmt_Else:
    def __init__(self, stmts) -> None:
        self.stmts = stmts

    def __str__(self) -> str:
        return 'Else({})'.format(self.stmts)