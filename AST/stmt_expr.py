class Stmt_Expression:
    def __init__(self, expr) -> None:
        self.expr = expr
        self.sources = []
        self.sanitizers = []
    
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

    def __str__(self) -> str:
        return 'Stmt_Expression({})'.format(self.expr)