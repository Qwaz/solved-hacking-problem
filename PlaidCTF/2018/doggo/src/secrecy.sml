structure Secrecy =
struct
datatype t
  = Private
  | Public

fun leq Private Public = false
  | leq _ _ = true

fun max (Public, Public) = Public
  | max _ = Private

fun min (Private, Private) = Private
  | min _ = Public

(* shows a prefix if different from the first parameter *)
fun toPrefix Private = "private "
  | toPrefix Public = ""

end

