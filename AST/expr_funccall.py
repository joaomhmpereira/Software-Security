class Expr_FuncCall:
    def __init__(self, name, args, _type) -> None:
        self.name = name
        self.args = args
        self.type = _type
        self.sanitizers = []
        self.sanitized_sources = []
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
    
    def get_sanitized_sources(self) -> list:
        return self.sanitized_sources

    def add_sanitized_sources(self, sources) -> None:
        for source in sources:
            if source not in self.sanitized_sources:
                self.sanitized_sources.append(source)
    
    def set_sanitized_sources(self, sanitized_sources) -> None:
        self.sanitized_sources = sanitized_sources

    def set_sources(self, sources) -> None:
        self.sources = sources

    def set_sanitizers(self, sanitizers) -> None:
        self.sanitizers = sanitizers
    
    def get_name(self) -> str:
        return self.name
    
    def get_sanitizers(self) -> list:
        return self.sanitizers
    
    def __repr__(self) -> str:
        return 'Function Call({}, FArgs: {}, FSources: {}, FSanitizers: {}, FSanSources: {})'.format(self.name, self.args, self.sources, self.sanitizers, self.sanitized_sources)