class Symbol_Stack:
    def __init__(self, symbol_table) -> None:
        self.symbol_tables = [symbol_table]
    
    def get_head(self):
        return self.symbol_tables[0]
    
    def get_tail(self):
        return self.symbol_tables[-1]
    
    def push(self, symbol_table) -> None:
        self.symbol_tables.append(symbol_table)
    
    def pop(self):
        last = self.symbol_tables[-1]
        self.symbol_tables = self.symbol_tables[:-1]
        return last
    
    def __repr__(self):
        return "Sym Stack: {}".format(self.symbol_tables)