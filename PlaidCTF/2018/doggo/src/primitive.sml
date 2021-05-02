signature PRIMITIVE =
sig
    type int
    datatype arith
      = Add
      | Sub
      | Mul
      | Quot
      | Rem
    datatype cmp
      = Eq
      | Gt
      | Lt
      | Ge
      | Le

    val int_of_decimal : string -> int
    val int_of_bytes : Word8Vector.vector -> int
    val int_to_decimal : int -> string

    val eval : arith -> int -> int -> int
    val compare : cmp -> int -> int -> bool
end

structure Primitive :> PRIMITIVE =
struct
datatype arith
  = Add
  | Sub
  | Mul
  | Quot
  | Rem
datatype cmp
  = Eq
  | Gt
  | Lt
  | Ge
  | Le

type cti = Word8.word Array.array
datatype t = BigInt of cti

local
    val (get_sib, _) = _symbol "BIGINT_SIZE_IN_BYTES" public: (unit -> int) * (int -> unit);
    val (get_num_bits, _) = _symbol "BIGINT_NUM_BITS" public: (unit -> word) * (word -> unit);
in
val bigint_size_in_bytes = get_sib ()
val bigint_num_bits = get_num_bits ()
end

local
    val bigint_init = _import "bigint_init" public: cti -> unit;
    val bigint_set_word = _import "bigint_set_word" public: (cti * word) -> unit;
in
(* allocate and initialize a cti to have the given value, or NaN if NONE*)
fun create_cti (x : word option) : cti =
  let val cti_buf : cti = Array.array(bigint_size_in_bytes, 0w0)
  in
      bigint_init cti_buf;
      Option.app (fn x => bigint_set_word (cti_buf, x)) x;
      cti_buf
  end
end

(* Comparison *)
val bigint_eq = _import "bigint_eq" public : (cti * cti) -> bool;
val bigint_lt = _import "bigint_lt" public : (cti * cti) -> bool;
val bigint_gt = _import "bigint_gt" public : (cti * cti) -> bool;
val bigint_le = _import "bigint_le" public : (cti * cti) -> bool;
val bigint_ge = _import "bigint_ge" public : (cti * cti) -> bool;

(* Arithmetic *)
val bigint_add = _import "bigint_add" public : (cti * cti * cti) -> unit;
val bigint_sub = _import "bigint_sub" public : (cti * cti * cti) -> unit;
val bigint_mul = _import "bigint_mul" public : (cti * cti * cti) -> unit;
val bigint_quot = _import "bigint_quot" public : (cti * cti * cti) -> unit;
val bigint_rem = _import "bigint_rem" public : (cti * cti * cti) -> unit;

fun compare cmp_op =
  let val do_cmp =
          case cmp_op
           of Eq => bigint_eq
            | Gt => bigint_gt
            | Lt => bigint_lt
            | Ge => bigint_ge
            | Le => bigint_le
  in
      fn BigInt cti_x =>
         fn BigInt cti_y =>
            do_cmp (cti_x, cti_y)
  end

fun eval arith_op (BigInt cti_a) (BigInt cti_b) =
  let val cti_result = create_cti NONE
  in
      case arith_op
       of Add => bigint_add (cti_result, cti_a, cti_b)
        | Sub => bigint_sub (cti_result, cti_a, cti_b)
        | Mul => bigint_mul (cti_result, cti_a, cti_b)
        | Quot => bigint_quot (cti_result, cti_a, cti_b)
        | Rem => bigint_rem (cti_result, cti_a, cti_b);
      BigInt cti_result
  end

local
    val bigint_read_from_bytes = _import "bigint_read_from_bytes" public: cti * Word8Vector.vector * word -> unit;
    val bigint_copy = _import "bigint_copy" public: cti * cti -> unit;
    val bigint_neg = _import "bigint_neg" public: cti * cti -> unit;
    val bigint_isnan = _import "bigint_isnan" public: cti -> bool;
    val bigint_eq0 = _import "bigint_eq0" public: cti -> bool;
    val bigint_lt0 = _import "bigint_lt0" public: cti -> bool;
    val bigint_to_word = _import "bigint_to_word" public: cti -> word;
    val bigint_quotrem = _import "bigint_quotrem" public: cti * cti * cti * cti -> unit;

    val cti_ten = create_cti (SOME 0w10)
    val decimal_digits = List.tabulate (10, create_cti o SOME o Word.fromInt)

    exception NaN
    exception Zero
    exception IntMin
in
fun int_of_bytes bytes : t =
  let val cti_result = create_cti NONE
  in
      bigint_read_from_bytes (cti_result, bytes, Word.fromInt (Word8Vector.length bytes));
      BigInt cti_result
  end

fun int_of_decimal s =
  let val cti_acc = create_cti (SOME 0w0)
      fun digit_to_cti c = List.nth (decimal_digits, Char.ord c - Char.ord #"0")
                           handle Subscript => raise Fail "Not a digit"
  in
      List.app
          (fn c =>
              (bigint_mul (cti_acc, cti_acc, cti_ten);
               bigint_add (cti_acc, cti_acc, digit_to_cti c))
          )
          (String.explode s);
      BigInt cti_acc
  end

fun int_to_decimal (BigInt cti_x) =
  (* Not constant-time, but we only use this when revealing a value at the end *)
  let val quot = create_cti NONE
      val rem = create_cti NONE
      val acc : char list ref = ref []
      val prefix = ref ""
  in
      if bigint_isnan(cti_x)
      then raise NaN
      else if bigint_eq0(cti_x)
      then raise Zero
      else if bigint_lt0(cti_x)
      then (bigint_neg(quot, cti_x);
            prefix := "~")
      else bigint_copy(quot, cti_x);
      if bigint_isnan(quot)
      then raise IntMin
      else ();
      while (not (bigint_eq0(quot))) do
            (bigint_quotrem(quot, rem, quot, cti_ten);
             let val digit = bigint_to_word rem
                 val c = Char.chr (Char.ord #"0" + Word.toInt digit)
             in acc := c :: !acc end
            );
      !prefix ^ String.implode (!acc)
  end handle NaN => "NaN"
           | Zero => "0"
           | IntMin => IntInf.toString (IntInf.~(IntInf.<<(1, bigint_num_bits)))
end

type int = t
end
