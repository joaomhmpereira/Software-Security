class Arg:
    def __init__(self, value,) -> None:
        self.value = value
        self.sources = self.value.sources
        self.sanitizers = self.value.sanitizers
        self.sanitized_sources = self.value.sanitized_sources

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

    def __repr__(self) -> str:
        return 'Arg(Value: {}, ASources: {}, ASanitizers: {}, ASanSources: {})'.format(self.value, self.sources, self.sanitizers, self.sanitized_sources)