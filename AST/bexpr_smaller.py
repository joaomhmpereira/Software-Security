class BExpr_Smaller:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return 'Smaller({} < {})'.format(self.left, self.right)