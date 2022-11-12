package alacs

import scalanative.unsafe._, Nat._
import scalanative.libc._

case class InterpError(msg: String) extends Exception(msg)
private def error(msg: String): Nothing = throw InterpError(msg)

object Interp {
  def getValue(v: Value): Int = v match {
    case IntV(v) => v
    case BooleanV(v) => if(v == true) 1 else 0
    case ArrayV(vs) => vs(0)
    case NilV => 0
    case CloV(_, _) => error(s"Function is not value")
  }

  def interp(expr: Expr, env: Env): Value = expr match {
    case Id(n) => env.getEnv(n) match {
      case NilV => NilV
      case x: Value => x
    }
    
    case IntE(v) => IntV(v)
    case BooleanE(v) => BooleanV(v)
    case Function(p, b) => CloV(p, b)
    case NilE => NilV
    case ArrayE(vs) => ArrayV(vs)

    case Add(l, r) => IntV(getValue(interp(l,env)) + getValue(interp(r,env)))
    case Mul(l, r) => IntV(getValue(interp(l,env)) * getValue(interp(r,env)))
    case Div(l, r) => {
      val left  = getValue(interp(l,env))
      val right = getValue(interp(r,env))
      if (right == 0) error(s"Zero division")
      else IntV(left / right)
    }
    case Mod(l, r) => {
      val left  = getValue(interp(l,env))
      val right = getValue(interp(r,env))
      if (right == 0) error(s"Zero division")
      else IntV(left % right)
    }

    case Eq(l, r) => {
      val left  = getValue(interp(l,env))
      val right = getValue(interp(r,env))
      
      if (left == right) BooleanV(true)
      else BooleanV(false)
    }
    case Neq(l, r) => {
      val left  = getValue(interp(l,env))
      val right = getValue(interp(r,env))
      
      if (left != right) BooleanV(true)
      else BooleanV(false)
    }
    case Lt(l, r) => {
      val left  = getValue(interp(l,env))
      val right = getValue(interp(r,env))
      
      if (left < right) BooleanV(true)
      else BooleanV(false)
    }

    case App(f, a) => {
      val func = interp(f, env)
      val interpret = a => interp(a, env)
      func match {
        case CloV(x, b) => 
          if (x.length != a.length) error(s"Mismatch argument: $f")
          val newEnv = env.cloneEnv()

          x.zip(a.map(interpret)).toMap.foreach {
            case (key: String, value: Value) => {
              newEnv.getEnv(key) match {
                case NilV => newEnv.addEnv(key, value)
                case _ => newEnv.setEnv(key, value)
              }
            }
          }
          interp(b, newEnv)
        case _ => error(s"Not Clouser: $f")
      }
    }

    case If(c, t, f) => if (getValue(interp(c, env)) != 0) interp(t, env) else interp(f, env)
    case Val(n, e) => env.getEnv(n) match {
      case NilV => 
        val value = interp(e, env)
        val idx = env.addEnv(n, value)
        value
      case x: Value => error(s"Duplicate Id: $n")
    }

    case GetArray(n, i) => env.getEnv(n) match {
      case ArrayV(vs) => IntV(vs(i))
      case NilV => error(s"Not Such Id: $n")
      case _ => error(s"Not Array: $n")
    }

    case SetArray(n, i, e) => env.getEnv(n) match {
      case ArrayV(vs) => {
        interp(e, env) match {
          case IntV(v) => {
            val res = env.setArrayIndex(n, i, v) 
            res match {
              case ""  => IntV(v)
              case _ => error(res) 
            }
          }
          case _ => error(s"Not Int Type")
        }
      }
      case NilV => error(s"Not Such Id: $n")
      case _ => error(s"Not Array: $n")
    }
  }
}

