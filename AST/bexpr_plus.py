class BExpr_Plus:
    def __init__(self, left, right) -> None:
        self.left = left
        self.right = right
        self.sources = self.left.sources + self.right.sources
        self.sanitizers = self.left.sanitizers + self.right.sanitizers
        self.sanitized_sources = self.left.sanitized_sources + self.right.sanitized_sources

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

    def __str__(self) -> str:
        return 'Plus({} + {})'.format(self.left, self.right)