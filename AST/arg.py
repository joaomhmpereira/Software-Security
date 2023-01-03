from AST.expression import Expression

class Arg(Expression):
    def __init__(self, value) -> None:
        super().__init__()
        self.value = value
        self.set_sources(self.value.get_sources())
        self.set_sanitizers(self.value.get_sanitizers())
        self.set_sanitized_sources(self.value.get_sanitized_sources())

    def __repr__(self) -> str:
        return 'Arg(Value: {}, ASources: {}, ASanitizers: {}, ASanSources: {})'.format(self.value, self.get_sources(), self.get_sanitizers(), self.get_sanitized_sources())