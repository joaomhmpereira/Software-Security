class Expr_Assign:
    def __init__(self, lval, rval) -> None:
        self.lval = lval
        self.rval = rval

    def __str__(self) -> str:
        return 'Assignment({} = {})'.format(self.lval, self.rval)