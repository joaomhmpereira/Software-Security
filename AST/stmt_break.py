class Stmt_Break:
    def __init__(self, num) -> None:
        self.num = num

    def __str__(self) -> str:
        return 'Break({})'.format(self.num)