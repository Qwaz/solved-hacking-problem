signature COMPILE =
sig
    val compile : Language.term -> Language.term Computation.t
end

structure Compile :> COMPILE =
struct

fun impossible () = raise Fail "Impossible!"

open Language
open Computation.Ops
infix 1 >>= <&> $>
infix 4 <$> <*>

fun substInto (u, t) s =
  let val rec subst =
       fn existing as VarExp v => if v = u then s else existing
        | LetExp {dec=(v, exp), body} =>
          LetExp {dec=(v, subst exp), body=subst body}
        | LamExp {param, paramType, body} =>
          LamExp {param = param, paramType=paramType, body=subst body}
        | AppExp {function, argument} =>
          AppExp {function=subst function, argument=subst argument}
        | PrimCmp (prim, (arg1, arg2)) =>
          PrimCmp (prim, (subst arg1, subst arg2))
        | PrimArith (prim, (arg1, arg2)) =>
          PrimArith (prim, (subst arg1, subst arg2))
        | IfExp {cond, thenCase, elseCase} =>
          IfExp {cond=subst cond, thenCase=subst thenCase, elseCase=subst elseCase}
        | NewRefExp e => NewRefExp (subst e)
        | AssignExp {target, value} => AssignExp {target=subst target, value=subst value}
        | DerefExp e => DerefExp (subst e)
        | CoerceExp (e, t) => CoerceExp (subst e, t)
        | noFreeVars as IntExp _ => noFreeVars
        | noFreeVars as BoolExp _ => noFreeVars
        | noFreeVars as UnitExp => noFreeVars
        | noFreeVars as Reference _ => noFreeVars
  in
      subst t
  end

val rec eval : Language.term -> Language.term Computation.t =
 fn VarExp _ => impossible ()
  | LetExp {dec=(v, exp), body} =>
    eval exp <&> substInto (v, body) >>= eval
  | AppExp {function, argument} =>
    (substInto o castLam) <$> eval function <*> eval argument >>= eval
  | PrimCmp (prim, (arg1, arg2)) =>
    let fun do_eq x y =
          BoolExp
              (case (x, y)
                of (IntExp i1, IntExp i2) => Primitive.compare Primitive.Eq i1 i2
                 | (BoolExp b1, BoolExp b2) => b1 = b2
                 | (UnitExp, UnitExp) => true
                 | (Reference a1, Reference a2) => a1 = a2
                 | _ => impossible ())
    in
        case prim
         of Primitive.Eq => do_eq <$> eval arg1 <*> eval arg2
          | cmp =>
            (Primitive.compare
                 cmp
                 <$>
                 (castInt <$> eval arg1)
                 <*>
                 (castInt <$> eval arg2))
                <&> BoolExp
    end
  | PrimArith (prim, (arg1, arg2)) =>
    IntExp <$> (Primitive.eval prim <$> (castInt <$> eval arg1) <*> (castInt <$> eval arg2))
  | IfExp {cond, thenCase, elseCase} =>
    eval cond <&> castBool >>= Computation.branch (eval thenCase, eval elseCase)
  | NewRefExp e => eval e >>= Computation.new <&> Reference
  | AssignExp {target, value} =>
    Computation.join (Computation.set <$> (eval target <&> castAssignable) <*> eval value) $> UnitExp
  | DerefExp e => eval e <&> castAssignable >>= Computation.get
  | CoerceExp (e, _) => eval e
  | value as LamExp _ => Computation.pure value (* lambdas are values *)
  | value as IntExp _ => Computation.pure value
  | value as BoolExp _ => Computation.pure value
  | value as Reference _ => Computation.pure value
  | value as UnitExp => Computation.pure value

val compile = eval

end
