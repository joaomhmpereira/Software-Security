class BExpr_Greater:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return 'Greater({} > {})'.format(self.left, self.right)