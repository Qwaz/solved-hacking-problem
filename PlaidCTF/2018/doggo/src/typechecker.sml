signature TYPECHECKER =
sig
    val typecheck : Language.term -> Language.tycon
end

structure Typechecker :> TYPECHECKER =
struct
open Language
infix 3 @:
infix 4 +$
val op +$ = Secrecy.max
infix 5 *$
val op *$ = Secrecy.min

structure Context = SplayMapFn(Variable)
type context = tycon Context.map

fun checkType ty : unit =
  case ty
   of Carrow (t1, t2 as (_ @: s')) @: s =>
      (checkType t1;
       checkType t2;
       if Secrecy.leq s s'
       then ()
       else raise TypeError.badType ty)
    | Cref _ @: Secrecy.Private => raise TypeError.badType ty
    | Cref t @: Secrecy.Public => checkType t
    | Cint @: _ => ()
    | Cbool @: _ => ()
    | Cunit @: _ => ()

fun subtype ((t1 @: s1) : tycon, (t2 @: s2) : tycon) : bool =
  Secrecy.leq s2 s1 andalso
  case (t1, t2)
   of (Cunit, Cunit) => true
    | (Carrow (c1, c2), Carrow (c1', c2')) =>
      subtype (c1', c1) andalso subtype (c2, c2')
    | (Cint, Cint) => true
    | (Cbool, Cbool) => true
    | (Cref c1, Cref c2) => equiv (c1, c2)
    | _ => false
and equiv (t1, t2) : bool =
    subtype (t1, t2) andalso subtype (t2, t1)

fun checkPrimCmp (prim, argtypes) =
  let open Primitive
  in case (prim, argtypes)
      of (Eq, (Cint @: s1, Cint @: s2)) => Cbool @: (s1 +$ s2)
       | (Eq, (Cbool @: s1, Cbool @: s2)) => Cbool @: (s1 +$ s2)
       | (Eq, (Cunit @: s1, Cunit @: s2)) => Cbool @: (s1 +$ s2)
       | (Eq, (Carrow _ @: _, Carrow _ @: _)) => raise TypeError.comparingFunctions
       | (Eq, (c1 as (Cref _ @: s1), c2 as (Cref _ @: s2))) =>
         if equiv (c1, c2)
         then Cbool @: (s1 +$ s2)
         else raise TypeError.comparingDifferentTypes
       | (Gt, (Cint @: s1, Cint @: s2)) => Cbool @: (s1 +$ s2)
       | (Lt, (Cint @: s1, Cint @: s2)) => Cbool @: (s1 +$ s2)
       | (Ge, (Cint @: s1, Cint @: s2)) => Cbool @: (s1 +$ s2)
       | (Le, (Cint @: s1, Cint @: s2)) => Cbool @: (s1 +$ s2)
       | (Eq, _) => raise TypeError.comparingDifferentTypes
       | (Gt, _) => raise TypeError.comparingUnorderableTypes
       | (Lt, _) => raise TypeError.comparingUnorderableTypes
       | (Ge, _) => raise TypeError.comparingUnorderableTypes
       | (Le, _) => raise TypeError.comparingUnorderableTypes
  end

fun checkPrimArith (prim, argtypes) =
  let open Primitive
  in case (prim, argtypes)
      of (Add, (Cint @: s1, Cint @: s2)) => Cint @: (s1 +$ s2)
       | (Sub, (Cint @: s1, Cint @: s2)) => Cint @: (s1 +$ s2)
       | (Mul, (Cint @: s1, Cint @: s2)) => Cint @: (s1 +$ s2)
       | (Quot, (Cint @: s1, Cint @: s2)) => Cint @: (s1 +$ s2)
       | (Rem, (Cint @: s1, Cint @: s2)) => Cint @: (s1 +$ s2)
       | (Add, _) => raise TypeError.arithNotInts
       | (Sub, _) => raise TypeError.arithNotInts
       | (Mul, _) => raise TypeError.arithNotInts
       | (Quot, _) => raise TypeError.arithNotInts
       | (Rem, _) => raise TypeError.arithNotInts
  end

infixr 2 <<<
datatype 'a and_purity
  = <<< of Secrecy.t * 'a (* What's the highest security ref that we write to *)

val doesn'tWrite = Secrecy.Private

fun checkTerm (cxt : context) : term -> tycon and_purity =
  fn VarExp v => doesn'tWrite <<< Context.lookup(cxt, v)
  | LetExp {dec=(x, exp), body} =>
    let val p <<< t = checkTerm cxt exp
        val cxt = Context.insert(cxt, x, t)
        val p' <<< bodyT = checkTerm cxt body
    in
        (p *$ p') <<< bodyT
    end
  | LamExp {param, paramType, body} =>
    let val cxt = Context.insert(cxt, param, paramType)
        val purity <<< returnType  = checkTerm cxt body
        val (_ @: returnSecrecy) = returnType
    in
        checkType paramType;
        doesn'tWrite <<< Carrow(paramType, returnType) @: (returnSecrecy *$ purity)
    end
  | CoerceExp (e, tnew) =>
    let val purity <<< t = checkTerm cxt e
    in
        checkType tnew;
        if subtype (tnew, t)
        then purity <<< tnew
        else raise TypeError.cannotCoerce (t, tnew)
    end
  | AppExp {function, argument} =>
    let val argTermPurity <<< t = checkTerm cxt argument
    in
        case checkTerm cxt function
         of funTermPurity <<< Carrow (t1, t2) @: funPurity =>
            if equiv (t, t1)
            then (funPurity *$ funTermPurity *$ argTermPurity) <<< t2
            else raise TypeError.appIncompatible ((t1, t2), t)
          | _ <<< other => raise TypeError.appNotArrow other
    end
  | PrimCmp (prim, (arg1, arg2)) =>
    let val p1 <<< t1 = checkTerm cxt arg1
        val p2 <<< t2 = checkTerm cxt arg2
    in
        (p1 *$ p2) <<< checkPrimCmp (prim, (t1, t2))
    end
  | PrimArith (prim, (arg1, arg2)) =>
    let val p1 <<< t1 = checkTerm cxt arg1
        val p2 <<< t2 = checkTerm cxt arg2
    in
        (p1 *$ p2) <<< checkPrimArith (prim, (t1, t2))
    end
  | UnitExp => doesn'tWrite <<< (Cunit @: Secrecy.Public)
  | IntExp _ => doesn'tWrite <<< (Cint @: Secrecy.Public)
  | BoolExp _ => doesn'tWrite <<< (Cbool @: Secrecy.Public)
  | NewRefExp e =>
    let val purity <<< argty = checkTerm cxt e
    in
        purity <<< Cref argty @: Secrecy.Public
    end
  | Reference _ => raise Fail "Why is this here?"
  | DerefExp e =>
    let val purity <<< refType = checkTerm cxt e
        val innerType =
            case refType
             of Cref t @: Secrecy.Public => t
              | Cref _ @: Secrecy.Private => raise Fail "Secret refs shouldn't appear anywhere"
              | nonRef => raise TypeError.derefNonRef nonRef
    in
        (purity *$ secrecyOf innerType) <<< innerType
    end
  | AssignExp {target, value} =>
    let val p <<< refType = checkTerm cxt target
        val innerType =
            case refType
             of Cref innerType @: Secrecy.Public => innerType
              | Cref _ @: Secrecy.Private => raise Fail "Secret refs shouldn't appear anywhere"
              | other => raise TypeError.assignNonRef other
        val p' <<< t' = checkTerm cxt value
    in
        if equiv (innerType, t')
        then (p *$ secrecyOf innerType *$ p') <<< Cunit @: Secrecy.Public
        else raise TypeError.assignWrongType (refType, t')
    end
  | IfExp {cond, thenCase, elseCase} =>
    let val pCond <<< condT = checkTerm cxt cond
        val p1 <<< thenT = checkTerm cxt thenCase
        val p2 <<< elseT = checkTerm cxt elseCase
        val pbranches = p1 *$ p2
    in
        case condT
         of Cbool @: condSecrecy =>
            if equiv (thenT, elseT)
            then (case (condSecrecy, thenT)
                   of (Secrecy.Public, branchesT) => (pbranches *$ pCond) <<< branchesT
                    | (Secrecy.Private, _ @: Secrecy.Public) => raise TypeError.publicIfBranches
                    | (Secrecy.Private, _ @: Secrecy.Private) =>
                      case pbranches
                       of Secrecy.Public => raise TypeError.leakyIfBranches
                        | Secrecy.Private => pCond <<< thenT)
            else raise TypeError.differentIfBranches (thenT, elseT)
          | other =>
            raise TypeError.nonBoolIfCondition other
    end

fun printableType ty =
  (* Is it ok to show a value of this type to the user? *)
  case ty
   of (_ @: Secrecy.Private) => false
    | (Cref inner @: Secrecy.Public) => printableType inner
    | (_ @: Secrecy.Public) => true

fun typecheck term =
  let val _ <<< ty = checkTerm Context.empty term
  in if printableType ty
     then ty
     else raise TypeError.notPrintable ty
  end

end
