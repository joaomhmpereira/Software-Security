from AST.expression import Expression

class Expr_FuncCall(Expression):
    def __init__(self, name, args, _type) -> None:
        super().__init__()
        self.name = name
        self.args = args
        self.type = _type
        if _type == "source":
            super().set_sources([self.name])

    def is_source(self) -> bool:
        return self.type == "source"
    
    def is_sink(self) -> bool:
        return self.type == "sink"
    
    def is_sanitizer(self) -> bool:
        return self.type == "sanitizer"
    
    def set_sanitizers(self, sanitizers) -> None:
        self.sanitizers = sanitizers
    
    def get_name(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return 'Function Call({}, FArgs: {}, FSources: {}, FSanitizers: {}, FSanSources: {})'.format(self.name, self.args, self.sources, self.sanitizers, self.sanitized_sources)