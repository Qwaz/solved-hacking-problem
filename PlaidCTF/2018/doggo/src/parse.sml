signature PARSER =
sig
    exception ParseError of string
    (* Give the variable id of the flag *)
    val parse : Variable.t -> string -> Language.term Result.t
end

structure Parser :> PARSER =
struct
exception ParseError of string
structure VarMapping = SplayMapFn(struct
                                   open String
                                   type ord_key = string
                                   end)
type vmap = Variable.t VarMapping.map

open Parse
infix 1 <|> >>=
infix  3 <*> <* *>
infixr 4 <$> <$$> <$$$> <$ <$?>

fun unrecoverableError msg : 'a Parse.t =
  (fn {line, column} =>
      raise ParseError (msg ^ " at " ^ Int.toString line ^ ":" ^ Int.toString column)
  ) <$> location

fun foldr1 f l =
  case l of
      [x] => x
    | (x :: xs) => f (x, foldr1 f xs)
    | [] => raise Fail "foldr1 empty list!"

fun foldl1 f l =
  case l of
      [x] => x
    | (x :: y :: xs) => foldl1 f (f (x, y) :: xs)
    | [] => raise Fail "foldl1 empty list!"

val reserved =
    [ "public"
    , "private"
    , "int"
    , "bool"
    , "unit"
    , "ref"
    , "if"
    , "then"
    , "else"
    , "let"
    , "in"
    , "fn"
    , "true"
    , "false"
    ]

(* Extra combinators for operator parsing *)
fun parse2 parsers = (fn x => x) <$$> parsers

fun parseInfixL (symbolParser, innerParser) =
  let fun parseInfix' prev =
        (parse2 (symbolParser, innerParser)
                >>=
                (fn (mkNode, next) => parseInfix' (mkNode (prev, next)))
        ) <|> pure prev
  in
      innerParser >>= parseInfix'
  end

fun parseInfixR (symbolParser, innerParser) =
  let fun parseInfix' prev =
        ((fn (mkNode, tail) => mkNode(prev, tail))
             <$$>
             (symbolParser, innerParser >>= parseInfix')
        ) <|> pure prev
  in
      innerParser >>= parseInfix'
  end

(* parse multiple operators with successively increasing precedence *)
fun parseInfixesL infixparsers inner =
  List.foldr parseInfixL inner infixparsers

fun parseInfixesR infixparsers inner =
  List.foldr parseInfixR inner infixparsers

fun parsePrefixes prefixparser inner =
  many prefixparser >>= List.foldr (op <$>) inner

fun parsePostfixes (postfixparser : ('a -> 'a) t) (inner : 'a t) : 'a t =
  inner >>= (fn inner => List.foldl (fn (f, x) => f x) inner <$> many postfixparser)

val identifierStart = nextSat Char.isAlpha
val identifierBody = nextSat (fn c => Char.isAlphaNum c orelse c = #"_")

fun parse flag_var s =
  let open Language
      infix @:
      fun lexeme p = p <* spaces
      fun literal s = () <$ lexeme (notFollowedBy (str s, identifierBody))
      fun literal' s = () <$ lexeme (str s) (* for operators *)
      val openParen = lexeme (notFollowedBy (str "(", str ")"))
      fun parens p = openParen *> cut p <* literal ")"
      fun checkIdent s =
        if List.exists (fn x => x = s) reserved
        then fail "identifier"
        else pure s

      val identifier = lexeme (
              ((String.implode o op ::)
                  <$$>
                  (identifierStart, many identifierBody))
                  >>= checkIdent
          )
      fun existingIdentifier cxt : Variable.t Parse.t =
        identifier
            >>=
            (fn name =>
                case VarMapping.find(cxt, name)
                 of SOME v => pure v
                  | NONE => unrecoverableError
                                ("Variable \"" ^ name ^ "\" not in scope"))

      fun parseTycon () =
        let fun makeRef t = Cref t @: Secrecy.Public
            fun makeFn inner = Carrow inner @: Secrecy.Public
        in
            parseInfixesR
                [makeFn <$ literal' "->"]
                (parsePrefixes
                     (makeRef <$ literal "ref"
                           <|> Language.classify <$ literal "private"
                           <|> Language.declassify <$ literal "public")
                     (any [ (Cint @: Secrecy.Public) <$ literal "int"
                          , (Cbool @: Secrecy.Public) <$ literal "bool"
                          , (Cunit @: Secrecy.Public) <$ literal "unit"
                          , parens (delay parseTycon)
                          , failCut "type constructor"])
                )
        end
      val parseTycon = parseTycon ()
      fun parseTerm (cxt : vmap) () =
        let
            fun makeSequence (e1, e2) =
              LetExp {dec = (Variable.newVar (), e1), body = e2}
            fun makeAppExp (function, argument) =
              AppExp {function=function, argument=argument}
            fun makeAssignExp (target, value) =
              AssignExp {target=target, value=value}
            fun makeIfExp (cond, thenCase, elseCase) =
              IfExp { cond = cond,
                      thenCase = thenCase,
                      elseCase = elseCase }
            val parseLet =
                literal "let" *> cut (
                parse2
                    (identifier <* literal' "=",
                     delay (parseTerm cxt) <* literal "in")
                    >>= (fn (ident, exp) => cut
                            let val newvar = Variable.newVar ()
                                val cxt' = VarMapping.insert(cxt, ident, newvar)
                            in
                                (fn body => LetExp {dec = (newvar, exp), body = body})
                                    <$>
                                    delay (parseTerm cxt')
                            end)
                )
            val parseLam =
                literal "fn" *> cut (
                parse2
                    (openParen *> identifier,
                     literal' ":" *> parseTycon <* literal' ")" <* literal' "=>")
                    >>= (fn (ident, tycon) =>
                            let val newvar = Variable.newVar ()
                                val cxt' = VarMapping.insert(cxt, ident, newvar)
                            in
                                (fn body => LamExp {param=newvar, paramType=tycon, body=body})
                                    <$>
                                    delay (parseTerm cxt')
                            end)
                )
            val parseIfExp =
                makeIfExp
                    <$$$>
                    (literal "if" *> cut (delay (parseTerm cxt)),
                     literal "then" *> cut (delay (parseTerm cxt)),
                     literal "else" *> cut (delay (parseTerm cxt)))
            fun makeArith primop ops = PrimArith (primop, ops)
            fun makeCmp primop ops = PrimCmp (primop, ops)
            fun parseApp inner = foldl1 makeAppExp <$> many1 inner
            val parseCoerce = literal' ":>" *> cut ((fn t => fn e => CoerceExp (e, t)) <$> parseTycon)
            val digits = notFollowedBy(many1 (nextSat Char.isDigit), nextSat Char.isDigit)
            val parseInt = (Primitive.int_of_decimal o String.implode) <$> digits  <|> failCut "integer"
        in
            parsePostfixes
                parseCoerce
                (parseInfixesL
                     [makeSequence <$ literal' ";",
                      makeAssignExp <$ literal' ":="
                                    <|> makeCmp Primitive.Eq <$ literal' "="
                                    <|> makeCmp Primitive.Gt <$ literal' ">"
                                    <|> makeCmp Primitive.Lt <$ literal' "<"
                                    <|> makeCmp Primitive.Le <$ literal' "<="
                                    <|> makeCmp Primitive.Ge <$ literal' ">=",
                      makeArith Primitive.Add <$ literal' "+"
                                <|> makeArith Primitive.Sub <$ literal' "-",
                      makeArith Primitive.Mul <$ literal' "*"
                                <|> makeArith Primitive.Quot <$ literal' "/"
                                <|> makeArith Primitive.Rem <$ literal' "%"
                     ]
                     (parseApp
                          (parsePrefixes
                               ((DerefExp <$ literal' "!")
                                    <|> (NewRefExp <$ literal "ref"))
                               ((any [ IntExp <$> lexeme parseInt
                                     , BoolExp true <$ literal "true"
                                     , BoolExp false <$ literal "false"
                                     , (UnitExp <$ literal' "()")
                                     , parseLet
                                     , (parens (delay (parseTerm cxt)))
                                     , parseIfExp
                                     , parseLam
                                     , (VarExp <$> existingIdentifier cxt)
                                     , failCut "expression"]
                )))))
        end
      val eof = (next *> failCut "eof") <|> pure ()
      val start_cxt = VarMapping.insert
                          (VarMapping.empty,
                           "flag",
                           flag_var)
  in
      parseString (spaces *> parseTerm start_cxt () <* eof, s)
  end
end
