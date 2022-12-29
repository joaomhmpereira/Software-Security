class BExpr_Concat:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return 'Concat({} . {})'.format(self.left, self.right)