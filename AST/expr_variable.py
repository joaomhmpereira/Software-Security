from AST.expression import Expression

class Expr_Variable(Expression):
    def __init__(self, name, _type) -> None:
        super().__init__()
        super().set_sources([name])
        self.name = name
        self.type = _type
    
    def get_name(self) -> str:
        return self.name
    
    def is_source(self) -> bool:
        return self.type == "source"
    
    def is_sink(self) -> bool:
        return self.type == "sink"
    
    def is_sanitizer(self) -> bool:
        return self.type == "sanitizer"
    
    def is_tainted(self) -> bool:
        return len(self.sources) > 0
        
    def __repr__(self) -> str:
        return 'Variable "{}", VSources: {}, VSanitizers: {}, VSanSources: {}'.format(self.name, self.sources, self.sanitizers, self.sanitized_sources)