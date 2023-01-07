class Stmt_Switch:
    def __init__(self, cond, cases) -> None:
        self.cond = cond
        self.cases = cases

    def __str__(self) -> str:
        return 'Stmt_Switch(Condition: {}, Cases: {})'.format(self.cond, self.cases)