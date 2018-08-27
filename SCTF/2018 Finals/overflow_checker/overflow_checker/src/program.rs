pub type Int = i32;
pub type Var = String;

pub type Block = Vec<Statement>;

#[derive(Debug)]
pub enum Compare {
    Eq(Var, Int),
    Lt(Var, Int),
    Le(Var, Int),
    Gt(Var, Int),
    Ge(Var, Int),
}

#[derive(Debug)]
pub enum Expression {
    Int(Int),
    Add(Box<Expression>, Box<Expression>),
    Input,
    Var(Var),
}

#[derive(Debug)]
pub enum Statement {
    Assign(Var, Expression),
    For {
        inc: Var,
        compare_to: Var,
        body: Block
    },
    IfElse {
        condition: Compare,
        if_body: Block,
        else_body: Block,
    },
    Expression(Expression),
}
