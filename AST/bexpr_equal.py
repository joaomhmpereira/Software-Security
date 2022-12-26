class BExpr_Equal:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return 'Equal({} == {})'.format(self.left, self.right)