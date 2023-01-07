class Stmt_For:
    def __init__(self, init, cond, loop, stmts) -> None:
        self.init = init
        self.cond = cond
        self.loop = loop
        self.stms = stmts

    def __str__(self) -> str:
        return 'Stmt_For(Init: {}, Condition: {}, Statements: {}, Loop: {})'.format(self.init, self.cond, self.stms, self.loop)