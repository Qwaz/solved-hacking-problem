structure Language =
struct

infix @:
datatype term
  = VarExp of Variable.t
  | LetExp of {
      dec : (Variable.t * term), (* declaration *)
      body : term
  }
  | LamExp of {
      param : Variable.t,
      paramType : tycon,
      body : term
  }
  | AppExp of { function : term, argument : term }
  | PrimArith of Primitive.arith * (term * term)
  | PrimCmp of Primitive.cmp * (term * term)
  | IfExp of {cond : term, thenCase : term, elseCase : term}
  | UnitExp
  | IntExp of Primitive.int
  | BoolExp of bool
  | NewRefExp of term
  | AssignExp of { target : term, value : term }
  | DerefExp of term
  | CoerceExp of term * tycon
  | Reference of Assignable.assignable

and tycon (* type constructors with secrecy *)
    = @: of con * Secrecy.t

and con (* type constructors *)
    = Cint
    | Cbool
    | Carrow of tycon * tycon
    | Cref of tycon
    | Cunit

(* Type of the flag *)
val private_int = Cint @: Secrecy.Private

(* Convenience functions *)
fun castInt (IntExp i) = i
  | castInt _ = raise Fail "Impossible!"

fun castBool (BoolExp b) = b
  | castBool _ = raise Fail "Impossible!"

fun castAssignable (Reference a) = a
  | castAssignable _ = raise Fail "Impossible!"

fun castLam (LamExp {param, body, ...}) = (param, body)
  | castLam _ = raise Fail "Impossible"

fun secrecyOf (_ @: cls) = cls

fun declassify (con @: _) =
  (con @: Secrecy.Public)

fun classify (con @: _) =
  (con @: Secrecy.Private)

fun tyconToString (con @: secrecy) =
  Secrecy.toPrefix secrecy ^
  (case con
   of Cint => "int"
    | Cbool => "bool"
    | Cunit => "unit"
    | Cref t => "ref(" ^ tyconToString t ^ ")"
    | Carrow (t1, t2) =>
      "(" ^ tyconToString t1 ^ " -> " ^ tyconToString t2 ^ ")")

fun valueToString store =
  fn IntExp i => Primitive.int_to_decimal i
  | UnitExp => "()"
  | BoolExp true => "true"
  | BoolExp false => "false"
  | LamExp _ => "fn"
  | Reference a => "ref " ^ (valueToString store (Assignable.Store.lookup (store, a)))
  | _ => raise Fail "Not a value!"

end
