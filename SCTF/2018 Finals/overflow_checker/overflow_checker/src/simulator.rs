use crate::program::*;

use std::cmp;
use std::collections::HashMap;

type RangePair = (i32, i32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    vec: Vec<RangePair>,
}

impl Range {
    pub fn new(vec: Vec<RangePair>) -> Self {
        let mut vec = vec;
        vec.sort();

        let mut result = Vec::new();
        let mut last_pair = None;
        for &(s, e) in vec.iter().filter(|(s, e)| s <= e) {
            match last_pair {
                Some((ls, le)) => {
                    last_pair = if s <= le + 1 {
                        Some((ls, cmp::max(le, e)))
                    } else {
                        result.push((ls, le));
                        Some((s, e))
                    }
                },
                None => last_pair = Some((s, e)),
            }
        }
        if let Some(pair) = last_pair {
            result.push(pair);
        }

        Self {
            vec: result,
        }
    }

    pub fn new_pair(pair: RangePair) -> Self {
        Self::new(vec!(pair))
    }

    pub fn merge(&self, range: &Self) -> Self {
        let mut result = Vec::new();
        for r in self.vec.iter() {
            result.push(r.clone());
        }
        for r in range.vec.iter() {
            result.push(r.clone());
        }

        Self::new(result)
    }

    pub fn overlap_range(&self, range: &Self) -> Self {
        let mut result = Vec::new();
        for &(ls, le) in range.vec.iter() {
            for &(s, e) in self.vec.iter() {
                let next_s = cmp::max(s, ls);
                let next_e = cmp::min(e, le);
                if next_s <= next_e {
                    result.push((next_s, next_e));
                }
            }
        }

        Self::new(result)
    }

    pub fn add(&self, other_range: &Self) -> Result<Self, ()> {
        let mut result = Vec::new();
        for &(s, e) in self.vec.iter() {
            for &(os, oe) in other_range.vec.iter() {
                let (new_s, overflow_s) =  s.overflowing_add(os);
                let (new_e, overflow_e) =  e.overflowing_add(oe);
                if overflow_s || overflow_e {
                    return Err(());
                }
                result.push((new_s, new_e));
            }
        }

        Ok(Self::new(result))
    }

    pub fn mul(&self, other_range: &Self) -> Result<Self, ()> {
        let mut result = Vec::new();
        for &(s, e) in self.vec.iter() {
            for &(os, oe) in other_range.vec.iter() {
                let (new_s, overflow_s) =  s.overflowing_mul(os);
                let (new_e, overflow_e) =  e.overflowing_mul(oe);
                if overflow_s || overflow_e {
                    return Err(());
                }
                result.push((new_s, new_e));
            }
        }

        Ok(Self::new(result))
    }
}

#[derive(Debug, Clone)]
pub struct State {
    map: HashMap<String, Range>,
}

impl State {
    pub fn new() -> State {
        State {
            map: HashMap::new(),
        }
    }

    pub fn get_range(&self, var: &str) -> Option<&Range> {
        self.map.get(var)
    }

    pub fn put_range(&mut self, var: &str, range: Range) {
        self.map.insert(var.to_string(), range);
    }

    pub fn merge(&self, state: &State) -> State {
        let mut new_state = State::new();

        let mut diff_found = false;
        for key in self.map.keys() {
            let r1 = self.get_range(key);
            let r2 = state.get_range(key);
            match (r1, r2) {
                (Some(r1), Some(r2)) => {
                    if r1 != r2 {
                        if !diff_found {
                            diff_found = true;
                            new_state.put_range(key, r1.merge(r2));
                        } else {
                            panic!("Too many state merge")
                        }
                    } else {
                        new_state.put_range(key, r1.clone());
                    }
                },
                _ => (),
            }
        }

        new_state
    }
}

pub fn run_block(block: &[Statement], state: State) -> Result<State, ()> {
    let mut state = state;
    for statement in block {
        state = run_statement(statement, state)?;
        eprintln!("After statement {:?}\n{:#?}", statement, state);
    }
    Ok(state)
}

fn run_statement(statement: &Statement, state: State) -> Result<State, ()> {
    let mut state = state;
    match statement {
        Statement::Expression(_) => Ok(state),
        Statement::Assign(var, e) => {
            state.put_range(&var, expression_range(e, &state)?);
            Ok(state)
        },
        Statement::IfElse {
            condition,
            if_body,
            else_body,
        } => {
            let (if_range, else_range) = compare_range(condition);

            let var = compare_var(condition);
            let mut if_state = state;
            let mut else_state = if_state.clone();

            if_state.put_range(&var, if_state.get_range(&var).expect("undefined variable")
                .overlap_range(&if_range));
            else_state.put_range(&var, else_state.get_range(&var).expect("undefined variable")
                .overlap_range(&else_range));

            let if_state = run_block(if_body, if_state)?;
            let else_state = run_block(else_body, else_state)?;

            Ok(if_state.merge(&else_state))
        },
        Statement::For {
            inc,
            compare_to,
            body,
        } => {
            let tmp_state = state.clone();
            let new_state = run_block(&body[..body.len()-1], tmp_state)?;

            if let Statement::Assign(
                var,
                Expression::Add(
                    box Expression::Var(var1), box Expression::Var(var2)
                )
            ) = &body[body.len()-1] {
                if var != var1 {
                    panic!("Unsupported for loop pattern");
                }

                let add_range = new_state.get_range(&var2).expect("Undefind variable in for loop")
                    .mul(state.get_range(&compare_to).expect("Undefind variable in for loop"))?;
                state.put_range(&var, state.get_range(&var).expect("Undefined variable in for loop")
                    .add(&add_range)?);

                return Ok(state);
            }

            panic!("Unsupported for loop pattern")
            /*
            let saved_state = state.clone();

            let mut current = 0;
            let mut output_state = None;
            let mut current_state = state;
            eprintln!("for loop range {:?}", saved_state.get_range(&compare_to));
            for &(s, e) in saved_state
                .get_range(&compare_to).expect("for comparison variable not found")
                .vec.iter() {
                while current < s-1 {
                    current_state = run_block(body, current_state)?;
                    current += 1;
                }

                while current < e {
                    current_state = run_block(body, current_state)?;
                    current += 1;

                    output_state = match output_state {
                        Some(output_inner_state) => Some(current_state.merge(&output_inner_state)),
                        None => Some(current_state.clone()),
                    };
                }
            }

            Ok(output_state.expect("for loop does not run"))
            */
        }
    }
}

fn expression_range(expression: &Expression, state: &State) -> Result<Range, ()> {
    match expression {
        Expression::Int(num) => Ok(Range::new_pair((*num, *num))),
        Expression::Add(e1, e2) => expression_range(&e1, state)?.add(&expression_range(&e2, state)?),
        Expression::Input => Ok(Range::new_pair((0, i32::max_value()))),
        Expression::Var(var) => match state.get_range(&var) {
            Some(range) => Ok(range.clone()),
            None => Err(()),
        },
    }
}

fn compare_var(compare: &Compare) -> Var {
    match compare {
        Compare::Eq(var, _) => var.clone(),
        Compare::Lt(var, _) => var.clone(),
        Compare::Le(var, _) => var.clone(),
        Compare::Gt(var, _) => var.clone(),
        Compare::Ge(var, _) => var.clone(),
    }
}

fn compare_range(compare: &Compare) -> (Range, Range) {
    match compare {
        Compare::Eq(_, num) => (
            Range::new_pair((*num, *num)),
            Range::new(vec!((0, num-1), (*num+1, i32::max_value()))),
        ),
        Compare::Lt(_, num) => (
            Range::new_pair((0, *num-1)),
            Range::new_pair((*num, i32::max_value())),
        ),
        Compare::Le(_, num) => (
            Range::new_pair((0, *num)),
            Range::new_pair((*num+1, i32::max_value())),
        ),
        Compare::Gt(_, num) => (
            Range::new_pair((*num+1, i32::max_value())),
            Range::new_pair((0, *num)),
        ),
        Compare::Ge(_, num) => (
            Range::new_pair((*num, i32::max_value())),
            Range::new_pair((0, *num-1)),
        )
    }
}
