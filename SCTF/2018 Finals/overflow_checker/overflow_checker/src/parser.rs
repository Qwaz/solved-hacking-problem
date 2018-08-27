use crate::program::*;

use pest::iterators::Pair as PestPair;
use pest::Error as PestError;
use pest::Parser;

#[derive(Parser)]
#[grammar = "parser.pest"]
struct ProgramParser;

type Pair<'i> = PestPair<'i, Rule>;
type Error<'i> = PestError<'i, Rule>;

pub fn parse_program(s: &str) -> Result<Vec<Statement>, Error> {
    let pairs = ProgramParser::parse(Rule::block, s)?;
    convert_block(&pairs.clone().next().unwrap())
}

fn convert_int<'a>(pair: &Pair<'a>) -> Result<Int, Error<'a>> {
    pair.as_str().trim().parse::<i32>()
        .map_err(|_| PestError::CustomErrorSpan {
            message: format!("failed to parse integer: {}", pair.as_str()),
            span: pair.clone().into_span(),
        })
}

fn convert_var<'a>(pair: &Pair<'a>) -> Result<Var, Error<'a>> {
    Ok(pair.as_str().to_string())
}

fn convert_block<'a>(pair: &Pair<'a>) -> Result<Vec<Statement>, Error<'a>> {
    // println!("Block - {:#?}", pair);
    pair.clone().into_inner().map(|pair| convert_statement(&pair)).collect()
}

fn convert_compare<'a>(pair: &Pair<'a>) -> Result<Compare, Error<'a>> {
    // println!("Compare - {:#?}", pair);
    let pair = pair.clone().into_inner().next().unwrap();
    let tokens: Vec<_> = pair.clone().into_inner().collect();
    // println!("Compare - {:#?}", tokens);

    let var = convert_var(&tokens[0])?;
    let int = convert_int(&tokens[1])?;
    match pair.as_rule() {
        Rule::eq => Ok(Compare::Eq(var, int)),
        Rule::lt => Ok(Compare::Lt(var, int)),
        Rule::le => Ok(Compare::Le(var, int)),
        Rule::gt => Ok(Compare::Gt(var, int)),
        Rule::ge => Ok(Compare::Ge(var, int)),
        rule => {
            Err(PestError::CustomErrorSpan {
                message: format!("unknown statement rule '{:?}'", rule),
                span: pair.clone().into_span(),
            })
        },
    }
}

fn convert_expression<'a>(pair: &Pair<'a>) -> Result<Expression, Error<'a>> {
    // println!("Expression - {:#?}", pair);
    let pair = pair.clone().into_inner().next().unwrap();
    let tokens: Vec<_> = pair.clone().into_inner().collect();
    // println!("Expression - {:#?}", tokens);

    match pair.as_rule() {
        Rule::int => Ok(Expression::Int(convert_int(&pair)?)),
        Rule::add => Ok(Expression::Add(
            Box::new(convert_expression(&tokens[0])?),
            Box::new(convert_expression(&tokens[1])?),
        )),
        Rule::input => Ok(Expression::Input),
        Rule::var => Ok(Expression::Var(convert_var(&pair)?)),
        rule => {
            Err(PestError::CustomErrorSpan {
                message: format!("unknown statement rule '{:?}'", rule),
                span: pair.clone().into_span(),
            })
        },
    }
}

fn convert_statement<'a>(pair: &Pair<'a>) -> Result<Statement, Error<'a>> {
    // println!("Statement - {:#?}", pair);
    let pair = pair.clone().into_inner().next().unwrap();
    let tokens: Vec<_> = pair.clone().into_inner().collect();
    // println!("Statement - {:#?}", tokens);

    match pair.as_rule() {
        Rule::assign =>
            Ok(Statement::Assign(
                convert_var(&tokens[0])?,
                convert_expression(&tokens[1])?)),
        Rule::for_loop => {
            let var0_0 = convert_var(&tokens[0])?;
            let var0_1 = convert_var(&tokens[1])?;
            let var0_2 = convert_var(&tokens[3])?;
            let var0_3 = convert_var(&tokens[4])?;
            let var1 = convert_var(&tokens[2])?;

            if var0_0 != var0_1 || var0_0 != var0_2 || var0_0 != var0_3 {
                return Err(PestError::CustomErrorSpan {
                    message: "variable name in for loop should match".to_string(),
                    span: pair.clone().into_span(),
                });
            }

            let body = convert_block(&tokens[5])?;

            Ok(Statement::For {
                inc: var0_0,
                compare_to: var1,
                body,
            })
        },
        Rule::if_else => {
            let condition = convert_compare(&tokens[0])?;
            let if_body = convert_block(&tokens[1])?;
            if tokens.len() == 2 {
                Ok(Statement::IfElse {
                    condition,
                    if_body,
                    else_body: Vec::new(),
                })
            } else {
                Ok(Statement::IfElse {
                    condition,
                    if_body,
                    else_body: convert_block(&tokens[2])?,
                })
            }
        },
        Rule::exp => Ok(Statement::Expression(convert_expression(&pair)?)),
        rule => {
            Err(PestError::CustomErrorSpan {
                message: format!("unknown statement rule '{:?}'", rule),
                span: pair.clone().into_span(),
            })
        },
    }
}
