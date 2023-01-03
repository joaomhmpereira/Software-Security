from AST.expression import Expression

class Binop_Expr(Expression):
    def __init__(self, left, right):
        super().__init__()
        self.left = left
        self.right = right
        
    def __str__(self):
        return "Binary_Expression(left: {}, right: {})".format(str(self.left), str(self.right))
    