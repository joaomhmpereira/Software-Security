class Expr_FuncCall:
    def __init__(self, name, args, _type) -> None:
        self.name = name
        self.args = args
        self.type = _type
        if _type == "source":
            self.sources = [self.name]
        else:
            self.sources = []
    
    def is_source(self) -> bool:
        return self.type == "source"
    
    def is_sink(self) -> bool:
        return self.type == "sink"
    
    def is_sanitizer(self) -> bool:
        return self.type == "sanitizer"
    
    def get_sources(self) -> list:
        return self.sources
    
    def add_source(self, source) -> None:
        if source not in self.sources:
            self.sources.append(source)
            
    def set_sources(self, sources) -> None:
        self.sources = sources
    
    def get_name(self) -> str:
        return self.name
    
    def get_sanitizers(self) -> list:
        return []
    
    def __str__(self) -> str:
        return 'Function Call({}, Args: {})'.format(self.name, self.args)