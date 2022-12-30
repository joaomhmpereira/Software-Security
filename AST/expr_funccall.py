class Expr_FuncCall:
    def __init__(self, name, args, _type) -> None:
        self.name = name
        self.args = args
        self.type = _type
    def __str__(self) -> str:
        return 'Function Call({}, Args: {})'.format(self.name, self.args)