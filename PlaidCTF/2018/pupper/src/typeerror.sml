signature TYPE_ERROR =
sig
    type tycon = Language.tycon
    exception TypeError of string

    val badType : tycon -> exn
    val cannotCoerce : (tycon * tycon) -> exn
    val arithNotInts : exn
    val comparingDifferentTypes : exn
    val comparingUnorderableTypes : exn
    val comparingFunctions : exn
    val appIncompatible : ((tycon * tycon) * tycon) -> exn
    val appNotArrow : tycon -> exn
    val differentIfBranches : (tycon * tycon) -> exn
    val nonBoolIfCondition : tycon -> exn
    val derefNonRef : tycon -> exn
    val assignNonRef : tycon -> exn
    val notPrintable : tycon -> exn
    val assignWrongType : (tycon * tycon) -> exn
end

structure TypeError :> TYPE_ERROR =
struct
open Language
exception TypeError of string

val arithNotInts = TypeError "Arithmetic operators can only operate on integers"
val comparingDifferentTypes = TypeError "Can only compare two arguments of the same type"
val comparingUnorderableTypes = TypeError "Can only order ints"
val comparingFunctions = TypeError "Functions are incomparable"

fun badType ty =
  TypeError ("Invalid type: " ^ tyconToString ty)

fun notPrintable ty =
  TypeError ("Cannot reveal secret value!\n(Program has type " ^ tyconToString ty ^ ")")

fun cannotCoerce (t1, t2) =
  TypeError (String.concat [
                  "Cannot Coerce:\n  ",
                  tyconToString t1,
                  " is not coercible to type ",
                  tyconToString t2
            ])

fun appIncompatible ((t1, _), t) =
  TypeError (String.concat [
                  "Function applied to argument of incorrect type:\n",
                  "  expects: ", tyconToString t1, "\n",
                  "  but got: ", tyconToString t
            ])

fun appNotArrow con =
  TypeError
      ( "Tried to apply a value of type "
        ^ tyconToString con
        ^ ", which is not a function type")

fun differentIfBranches (thenCase, elseCase) =
  TypeError (String.concat [
                  "Branches of if statement are different types: (",
                  tyconToString thenCase,
                  " and ",
                  tyconToString elseCase,
                  ")"
            ])

fun nonBoolIfCondition cond =
  TypeError
      ("Condition of if expression must be bool, not "
       ^ tyconToString cond)

fun derefNonRef t =
  TypeError
      ("Can only dereference references, not "
       ^ tyconToString t)

fun assignNonRef t =
  TypeError
      ("Can only assign to references, not "
       ^ tyconToString t)

fun assignWrongType (t, t') =
  TypeError (String.concat [
                  "Value assigned to reference of incompatible type:\n",
                  "  assigned value of type ", tyconToString t', "\n",
                  "  to a reference of type ", tyconToString t
            ])
end
