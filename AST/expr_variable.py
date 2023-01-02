class Expr_Variable:
    def __init__(self, name, _type) -> None:
        self.name = name
        self.sources = [name]
        self.sanitizers = []
        self.sanitized_sources = []
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

    def set_sanitizers(self, sanitizers) -> None:
        self.sanitizers = sanitizers
    
    def get_sanitized_sources(self) -> list:
        return self.sanitized_sources

    def add_sanitized_sources(self, sources) -> None:
        self.sanitized_sources.extend(sources)
    
    def set_sanitized_sources(self, sanitized_sources) -> None:
        self.sanitized_sources = sanitized_sources
    
    def is_source(self) -> bool:
        return self.type == "source"
    
    def is_sink(self) -> bool:
        return self.type == "sink"
    
    def is_sanitizer(self) -> bool:
        return self.type == "sanitizer"
    
    def is_tainted(self) -> bool:
        return len(self.sources) > 0
        
    def __str__(self) -> str:
        return 'Variable "{}", VSources: {}, VSanitizers: {}, VSanSources: {}'.format(self.name, self.sources, self.sanitizers, self.sanitized_sources)