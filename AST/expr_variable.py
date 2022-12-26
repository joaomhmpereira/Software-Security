class Expr_Variable:
    def __init__(self, id) -> None:
        self.id = id

    def __str__(self) -> str:
        return 'Variable "${}"'.format(self.id)