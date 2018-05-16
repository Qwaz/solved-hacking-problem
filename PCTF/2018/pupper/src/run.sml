val MAX_SOURCE_SIZE = 2048 (* more than enough... *)
val FLAG_LEN = 36
val INPUT_TIMEOUT = Time.fromSeconds 30
val EVALUATION_TIMEOUT = Time.fromSeconds 1
val TIMER_SIGNAL = MLton.Itimer.signal MLton.Itimer.Real

fun fail title msg =
  (MLton.Signal.setHandler(TIMER_SIGNAL, MLton.Signal.Handler.ignore);
   print (title ^ "\n" ^ msg ^ "\n");
   OS.Process.exit OS.Process.failure)

fun countdown length when_done =
  (MLton.Itimer.set(MLton.Itimer.Real, {interval=Time.zeroTime, value=Time.zeroTime});
   MLton.Signal.setHandler(TIMER_SIGNAL, MLton.Signal.Handler.simple when_done);
   MLton.Itimer.set(MLton.Itimer.Real, {interval=Time.zeroTime, value=length}))

val () = Posix.IO.dup2{old=Posix.FileSys.stdout, new=Posix.FileSys.stderr}
val () = countdown INPUT_TIMEOUT (fn () => fail "Timeout Error:" "Input/Parsing/Typechecking Timed out")

val flag =
    let val file = BinIO.openIn "flag.txt"
        val flag =
            BinIO.inputN(file, FLAG_LEN)
            before
            BinIO.closeIn file
    in  (* encode flag in an integer *)
        Primitive.int_of_bytes flag
    end

(* Read program from stdin *)
val source = TextIO.inputN(TextIO.stdIn, MAX_SOURCE_SIZE)

(* parse it and add the flag *)
val parsed =
    let
        val flag_var = Variable.newVar ()
        val userProgram =
            case Parser.parse flag_var source
                 handle Parser.ParseError msg => fail "Parse Error:" msg
             of Result.Yes parsed => parsed
              | Result.No reason => fail "Parse Error:" reason
        open Language
        val highSecrecyFlag = CoerceExp (IntExp flag, Language.private_int)
    in
        LetExp {
            dec = (flag_var, highSecrecyFlag),
            body = userProgram
        }
    end

(* Typecheck it *)
val ty = Typechecker.typecheck parsed
         handle TypeError.TypeError reason
                => fail "Type Error:" reason

val program = Compile.compile parsed

val () = countdown EVALUATION_TIMEOUT (fn () => fail "Timeout Error:" "Evaluation timed out")

(* Execute it and print the result *)
val () = let val (term, store) = Computation.run program
         in
             MLton.Signal.setHandler(TIMER_SIGNAL, MLton.Signal.Handler.ignore);
             print (Language.valueToString store term ^ " : " ^ Language.tyconToString ty ^ "\n")
         end
