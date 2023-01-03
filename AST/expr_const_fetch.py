class Expr_Const_Fetch:
    def __init__(self, name) -> None:
        self.name = name

    def __str__(self) -> str:
        return 'Const Fetch({})'.format(self.name)