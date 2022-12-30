class Arg:
    def __init__(self, value,) -> None:
        self.value = value

    def __repr__(self) -> str:
        return 'Arg(Value: {})'.format(self.value)