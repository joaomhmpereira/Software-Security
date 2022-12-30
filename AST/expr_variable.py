class Expr_Variable:
    def __init__(self, name, _type) -> None:
        self.name = name
        self.sources = [name]
        self.sanitizers = []
        self.type = _type
    
    def add_source(self, source) -> None:
        if source not in self.sources:
            self.sources.append(source)
            
    def del_source(self, source) -> None:
        if source in self.sources:
            self.sources.remove(source)
    
    def get_sources(self) -> list:
        return self.sources
    
    def get_sanitizers(self) -> list:
        return self.sanitizers
    
    def set_sources(self, sources) -> None:
        self.sources = sources
    
    def is_source(self) -> bool:
        return self.type == "source"
    
    def is_sink(self) -> bool:
        return self.type == "sink"
    
    def is_sanitizer(self) -> bool:
        return self.type == "sanitizer"
        
    def __str__(self) -> str:
        return 'Variable "{}"'.format(self.name)