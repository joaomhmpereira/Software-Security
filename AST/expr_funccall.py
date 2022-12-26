class Expr_FuncCall:
    def __init__(self, name, args) -> None:
        self.name = name
        self.args = args

    def __str__(self) -> str:
        return 'Function Call({}, Args: {})'.format(self.name, self.args)