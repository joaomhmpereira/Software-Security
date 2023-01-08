class Implicit_Checker:
    def __init__(self):
        self.stack_sources = []
        self.stack_sanitized_sources = []
        self.stack_sanitizers = []

    def push_source(self, item) -> None:
        self.stack_sources.append(item)
    
    def pop_source(self):
        item = self.stack_sources[-1]
        self.stack_sources = self.stack_sources[:-1]
        return item
    
    def get_head_source(self):
        return self.stack_sources[0]
    
    def get_tail_source(self):
        return self.stack_sources[-1]
    
    def get_flat_sources(self) -> list:
        sources = []
        for context in self.stack_sources:
            for source in context:
                if source not in sources:
                    sources.append(source)
        return sources
    
    def push_sanitized_source(self, item) -> None:
        self.stack_sanitized_sources.append(item)
    
    def pop_sanitized_source(self):
        item = self.stack_sanitized_sources[-1]
        self.stack_sanitized_sources = self.stack_sanitized_sources[:-1]
        return item
    
    def get_head_sanitized_source(self):
        return self.stack_sanitized_sources[0]
    
    def get_tail_sanitized_source(self):
        return self.stack_sanitized_sources[-1]
    
    def get_flat_sanitized_sources(self) -> list:
        sanitized_sources = []
        for context in self.stack_sanitized_sources:
            for sanitized_source in context:
                if sanitized_source not in sanitized_sources:
                    sanitized_sources.append(sanitized_source)
        return sanitized_sources
        
    def push_sanitizer(self, item) -> None:
        self.stack_sanitizers.append(item)
    
    def pop_sanitizer(self):
        item = self.stack_sanitizers[-1]
        self.stack_sanitizers = self.stack_sanitizers[:-1]
        return item
    
    def get_head_sanitizers(self):
        return self.stack_sanitizers[0]
    
    def get_tail_sanitizers(self):
        return self.stack_sanitizers[-1]
    
    def get_flat_sanitizers(self) -> list:
        sanitizers = []
        for context in self.stack_sanitizers:
            for group in context:
                sanitizers.append(group)
        return sanitizers

    def push(self, sources, sanitizers, sanitized_sources):
        self.push_source(sources)
        self.push_sanitizer(sanitizers)
        self.push_sanitized_source(sanitized_sources)

    def pop(self):
        self.pop_source()
        self.pop_sanitizer()
        self.pop_sanitized_source()

    def __repr__(self) -> str:
        return 'Implicit Checker: Sources -> {}, SanSources -> {}, Sanitizers -> {}'.format(self.stack_sources, self.stack_sanitized_sources, self.stack_sanitizers)