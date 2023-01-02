class Stmt_Expression:
    def __init__(self, expr) -> None:
        self.expr = expr
        self.sources = []
        self.sanitizers = []
        self.sanitized_sources = []
    
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
    
    def set_sources(self, sources) -> list:
        self.sources = sources
    
    def get_sanitized_sources(self) -> list:
        return self.sanitized_sources

    def add_sanitized_sources(self, sources) -> None:
        self.sanitized_sources.extend(sources)
    
    def set_sanitized_sources(self, sanitized_sources) -> None:
        self.sanitized_sources = sanitized_sources

    def __repr__(self) -> str:
        return 'Stmt_Expression({})'.format(self.expr)