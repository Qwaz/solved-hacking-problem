package alacs

import scalanative.unsafe._, Nat._
import scalanative.libc._
import scala.collection.mutable.Map

object Main {
  def app(env: Env): Int = {
    print(">> ")
    val input = scala.io.StdIn.readLine()
    input match {
      case "exit" => 0
      case "quit" => 0
      case _ => {
        try {
          val expr = Expr(input)
          val res  = Interp.interp(expr, env)
          val value = res match {
            case IntV(v) => v
            case BooleanV(v) => v
            case CloV(_, _) => "<function>"
            case ArrayV(v) => v
            case NilV => null    
          }
          println(value)
        } catch {
          case ex: Exception => println(ex)
        }
        app(env)
      }
    }
  }

  def main(args: Array[String]): Unit = {
    val env = Env()
    println("Welcome alacs v0.1")
    app(env)
  }
}
