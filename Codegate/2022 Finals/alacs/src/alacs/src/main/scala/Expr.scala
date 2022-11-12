package alacs

import scala.util.parsing.combinator._
import scala.collection.mutable.Map

sealed trait Expr
case class Id(name: String) extends Expr
case class IntE(value: Int) extends Expr
case class BooleanE(value: Boolean) extends Expr
case class ArrayE(values: List[Int]) extends Expr
case object NilE extends Expr
case class Add(left: Expr, right: Expr) extends Expr
case class Mul(left: Expr, right: Expr) extends Expr
case class Div(left: Expr, right: Expr) extends Expr
case class Mod(left: Expr, right: Expr) extends Expr
case class Eq(left: Expr, right: Expr) extends Expr
case class Neq(left: Expr, right: Expr) extends Expr
case class Lt(left: Expr, right: Expr) extends Expr
case class If(cond: Expr, trueBranch: Expr, falseBranch: Expr) extends Expr
case class Function(parameters: List[String], body: Expr) extends Expr
case class App(function: Expr, arguments: List[Expr]) extends Expr
case class Val(name: String, expression: Expr) extends Expr
case class GetArray(name: String, index: Int) extends Expr
case class SetArray(name: String, index: Int, value: Expr) extends Expr

sealed trait Value
case class IntV(value: Int) extends Value
case class BooleanV(value: Boolean) extends Value
case class CloV(parameters: List[String], body: Expr) extends Value
case class ArrayV(values: List[Int]) extends Value
case object NilV extends Value

case class ParsingError(msg: String) extends Exception

object Expr extends RegexParsers {
  private def error(msg: String): Nothing = throw ParsingError(msg)

  private def wrapBracket[T](e: Parser[T]): Parser[T] = "(" ~> e <~ ")"
  private def wrapArray[T](e: Parser[T]): Parser[T] = "[" ~> e <~ "]"

  val keywords = Set("true", "false", "Nil", "val", "if", "else")

  private lazy val int: Parser[Int] = "-?[0-9]+".r ^^ (_.toInt)
  private lazy val boolean: Parser[Boolean] = "true" ^^^ true | "false" ^^^ false
  private lazy val word: Parser[String] = "[a-zA-Z_][a-zA-Z0-9_]*".r.withFilter(!keywords(_))

  private lazy val idExpr: Parser[Expr] = 
    word ^^ Id.apply

  private lazy val intExpr: Parser[Expr] = 
    int ^^ IntE.apply

  private lazy val booleanExpr: Parser[Expr] = 
    boolean ^^ BooleanE.apply

  private lazy val nilExpr: Parser[Expr] = 
    "Nil" ^^^ NilE

  private lazy val arrExpr: Parser[Expr] = 
    (wrapArray(repsep(int, ","))) ^^ { case vs => ArrayE(vs) }

  private lazy val conditionExpr: Parser[Expr] = 
    (word <~ "==") ~ word ^^ { case l ~ r => Eq(Id(l), Id(r))  } | 
    (word <~ "!=") ~ word ^^ { case l ~ r => Neq(Id(l), Id(r)) } |
    (word <~ "<")  ~ word ^^ { case l ~ r => Lt(Id(l), Id(r))  }

  private lazy val arithmeticExpr: Parser[Expr] = 
    (word <~ "+") ~ word ^^ { case l ~ r => Add(Id(l), Id(r))  } | 
    (word <~ "*") ~ word ^^ { case l ~ r => Mul(Id(l), Id(r)) } |
    (word <~ "/") ~ word ^^ { case l ~ r => Div(Id(l), Id(r))  } |
    (word <~ "%") ~ word ^^ { case l ~ r => Mod(Id(l), Id(r))  }

  private lazy val callExpr: Parser[Expr] = 
    word ~ wrapBracket(repsep(expr, ",")) ^^ { case p ~ ps => App(Id(p), ps) }

  private lazy val valExpr: Parser[Expr] = 
    ("val" ~> word <~ "=") ~ expr  ^^ { case x ~ e => Val(x, e) }
  
  private lazy val ifExpr: Parser[Expr] = 
    ("if" ~> wrapBracket(expr)) ~ expr ~ ("else" ~> expr) ^^ { case c ~ t ~ f => If(c, t, f) }

  private lazy val functionExpr: Parser[Expr] =
    (word <~ "=>") ~ expr ^^ { case p ~ b => Function(List(p), b) } |
    (wrapBracket(repsep(word, ",")) <~ "=>") ~ expr ^^ { case ps ~ b => Function(ps, b) }

  private lazy val arrayGetExpr: Parser[Expr] = 
    word ~ (wrapArray(int)) ^^ { case n ~ i => GetArray(n, i) }
  
  private lazy val arraySetExpr: Parser[Expr] = 
    (word ~ (wrapArray(int))) ~ "=" ~ expr ^^ { case n ~ i ~ _ ~ e => SetArray(n, i, e) }

  private lazy val expr: Parser[Expr] = 
    functionExpr | valExpr | ifExpr | callExpr | arraySetExpr | arrayGetExpr |
    conditionExpr | arithmeticExpr | 
    idExpr | intExpr | booleanExpr | nilExpr | arrExpr
    
  def apply(str: String): Expr = parseAll(expr, str).getOrElse(error(""))
}