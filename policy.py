class Policy():
    def __init__(self, S, vulnerability):
        self.top = S
        self.bottom = []
        self.vulnerability = vulnerability
    
    def glb(self, set1, set2):
        '''
        Greatest lower bound operator: intersection
        '''
        return list(set(set1) & set(set2))
    
    def lub(self, set1, set2):
        '''
        Lowest upper bound operator: union
        '''
        return list(set(set1) | set(set2))
    
    def bottom(self):
        '''
        Lowest level of taintedness
        '''
        return self.bottom
    
    def top(self):
        '''
        Highest level of taintedness
        '''
        return self.top
    
    def can_flow(self, set0):
        '''
        Can-flow relation: order between the set of security levels
        '''
        ret = [[]]
        for i in range(len(set0) + 1):
            for j in range(i):
                ret.append(set0[j: i])
        return ret
    
    def get_vulnerability(self):
        return self.vulnerability
    
    