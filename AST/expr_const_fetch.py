from AST.expression import Expression

class Expr_Const_Fetch(Expression):
    def __init__(self, name) -> None:
        super().__init__()
        self.name = name

    def __str__(self) -> str:
        return 'Const Fetch({})'.format(self.name)