class Name:
    def __init__(self, parts) -> None:
        self.parts = parts

    def __str__(self) -> str:
        return 'Name(Parts: {})'.format(self.parts)