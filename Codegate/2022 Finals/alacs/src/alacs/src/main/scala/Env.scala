package alacs

import scalanative.unsafe._, Nat._
import scalanative.libc._
import scalanative.unsigned.UnsignedRichInt
import scala.collection.mutable.ListBuffer

type EnvN = CStruct4[CString, Ptr[Byte], CInt, CInt]
type _1024 = Digit4[_1, _0, _2, _4]
type EnvA  = CArray[Ptr[EnvN], _1024]


class Env {
  private val arr: EnvA = (stdlib.malloc(sizeof[EnvA])).asInstanceOf[Ptr[EnvA]]
  private var idx: Int = 0

  val INT:   CInt = 1
  val BOOL:  CInt = 2
  val NIL:   CInt = 3
  val FUNC:  CInt = 4
  val ARRAY: CInt = 5

  private def getCString(str: String): CString = {
    val size: CSize = Zone { implicit z => string.strlen(toCString(str)) }
    
    val name: CString = stdlib.malloc(size + 1.toULong).asInstanceOf[CString]
    Zone { implicit z => {
      string.strcpy(name, toCString(str))
    }}
    name
  }

  private def getString(str: CString): String =  Zone { implicit z => { fromCString(str) }}

  private def getArray(ptr: Ptr[EnvN]): List[Int] = {
    var arr = new ListBuffer[Int]()
    val arrSize = ptr._4
    for (i <- 0 to arrSize - 1) {
      val idx: CInt = i
      val value: Int = ((ptr._2).asInstanceOf[Ptr[CInt]])(idx)
      arr += value
    }
    arr.toList
  }

  private def setEnvN(ptr: Ptr[EnvN], name: CString, data: Ptr[Byte], typeT: Int, size: Int): Int = {
    ptr._1 = name
    ptr._2 = data
    ptr._3 = typeT
    ptr._4 = size
    !(arr.at(idx)) = ptr
    idx += 1
    idx
  }

  def addEnv(str: String, value: Value): Int = idx match {
    case x if x >= 1024 => -1
    case _ => {
      val name = getCString(str)
      val ptr = (stdlib.malloc(sizeof[EnvN])).asInstanceOf[Ptr[EnvN]]
      value match {
        case IntV(v) => 
          val intPtr = (stdlib.malloc(sizeof[CInt])).asInstanceOf[Ptr[CInt]]
          !intPtr = v
          setEnvN(ptr, name, intPtr.asInstanceOf[Ptr[Byte]], INT, 0)
        case BooleanV(v) => 
          val boolPtr = (stdlib.malloc(sizeof[CBool])).asInstanceOf[Ptr[CBool]]
          !boolPtr = v
          setEnvN(ptr, name, boolPtr.asInstanceOf[Ptr[Byte]], BOOL, 0)
        case NilV => 
          val nilPtr = (stdlib.malloc(sizeof[CInt])).asInstanceOf[Ptr[CInt]]
          !nilPtr = 0
          setEnvN(ptr, name, nilPtr.asInstanceOf[Ptr[Byte]], NIL, 0)
        case CloV(n, e) => 
          val cloPtr = (stdlib.malloc(sizeof[Value])).asInstanceOf[Ptr[Value]]
          !cloPtr = CloV(n, e)
          setEnvN(ptr, name, cloPtr.asInstanceOf[Ptr[Byte]], FUNC, 0)
        case ArrayV(vs) => 
          val arrSize: CInt = vs.length.toInt
          val arrPtr = (stdlib.malloc(sizeof[CInt] * vs.length.toULong)).asInstanceOf[Ptr[CInt]]
          for (i <- 0 to vs.length - 1) {
            arrPtr(i) = vs(i)
          }
          setEnvN(ptr, name, arrPtr.asInstanceOf[Ptr[Byte]], ARRAY, arrSize)
      }
    }
  }

  def setEnv(str: String, value: Value): Any = {
    val name = getCString(str)
    for (i <- 0 to idx - 1) {
      val ptr = !(arr.at(i))
      if (string.strcmp(name, ptr._1) == 0) return ptr._3 match {
        case INT  => !(ptr._2.asInstanceOf[Ptr[CInt]]) = value match { 
          case IntV(v) => v 
          case _ => 0
        }
        case BOOL => !(ptr._2.asInstanceOf[Ptr[CBool]]) = value match { 
          case BooleanV(v) => v 
          case _ => false
        }
        case NIL  => !(ptr._2.asInstanceOf[Ptr[CInt]]) = 0
        case FUNC => !(ptr._2.asInstanceOf[Ptr[Value]]) = value
        case ARRAY => {
          value match { 
            case ArrayV(vs) => {

              for (i <- 0 to vs.length - 1) {
                (ptr._2.asInstanceOf[Ptr[CInt]])(i) = vs(i)
              }
            } 
            case _ => None  
          }
        }
      }
    }
    None
  }

  def getEnv(str: String): Value = {
    val name = getCString(str)
    for (i <- 0 to idx - 1) {
      val ptr = !(arr.at(i))
      if (string.strcmp(name, ptr._1) == 0) ptr._3 match {
        case INT   => return IntV(!(ptr._2.asInstanceOf[Ptr[CInt]]))
        case BOOL  => return BooleanV(!(ptr._2.asInstanceOf[Ptr[CBool]]))
        case NIL   => return NilV
        case FUNC  => return !(ptr._2.asInstanceOf[Ptr[Value]])
        case ARRAY => return ArrayV(getArray(ptr))
      }
    }
    NilV
  }

  def cloneEnv(): Env = {
    val newEnv = Env()
    for (i <- 0 to idx - 1) {
      val ptr = !(arr.at(i))
      ptr._3 match {
        case INT   => newEnv.addEnv(getString(ptr._1), IntV(!(ptr._2.asInstanceOf[Ptr[CInt]])))
        case BOOL  => newEnv.addEnv(getString(ptr._1), BooleanV(!(ptr._2.asInstanceOf[Ptr[CBool]])))
        case NIL   => newEnv.addEnv(getString(ptr._1), NilV)
        case FUNC  => newEnv.addEnv(getString(ptr._1), !(ptr._2.asInstanceOf[Ptr[Value]]))
        case ARRAY => newEnv.addEnv(getString(ptr._1), ArrayV(getArray(ptr)))
      }
    }
    newEnv
  }

  def setArrayIndex(str: String, index: Int, value: Int): String = {
    val name = getCString(str)
    for (i <- 0 to idx - 1) {
      val ptr = !(arr.at(i))
      if (string.strcmp(name, ptr._1) == 0) return ptr._3 match {
        case ARRAY => {
          if (ptr._4 <= index) "Out Of Bound"
          else {
            (ptr._2.asInstanceOf[Ptr[CInt]])(index) = value
            ""
          }
        }
        case _ => "Not Array Type"
      }
    }
    "Not Such Id"
  }
}
