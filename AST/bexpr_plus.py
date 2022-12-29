class BExpr_Plus:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return 'Plus({} + {})'.format(self.left, self.right)