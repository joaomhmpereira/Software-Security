class Expression:
    def __init__(self) -> None:
        self.sources = []
        self.sanitizers = []
        self.sanitized_sources = []
    
    def get_sources(self) -> list:
        return self.sources
    
    def get_sanitizers(self) -> list:
        return self.sanitizers
    
    def get_sanitized_sources(self) -> list:
        return self.sanitized_sources
    
    def set_sources(self, sources) -> None:
        self.sources = sources
    
    def set_sanitizers(self, sanitizers) -> None:
        self.sanitizers = sanitizers
    
    def set_sanitized_sources(self, sanitized_sources) -> None:
        self.sanitized_sources = sanitized_sources
    
    def add_source(self, source) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def del_source(self, source) -> None:
        if source in self.sources:
            self.sources.remove(source)
    
    def add_sanitizer(self, sanitizer) -> None:
        if sanitizer not in self.sanitizers:
            self.sanitizers.append(sanitizer)
            
    def add_sanitized_sources(self, sanitized_sources) -> None:
        for sanitized_source in sanitized_sources:
            if sanitized_source not in self.sanitized_sources:
                self.sanitized_sources.append(sanitized_source)
        

