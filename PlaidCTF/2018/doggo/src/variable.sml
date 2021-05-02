signature VARIABLE =
sig
    eqtype t
    type ord_key = t
    val newVar : unit -> t
    val compare : t * t -> order
end

structure Variable :> VARIABLE =
struct
    type t = int
    type ord_key = t

    val counter = ref 0

    fun newVar () =
      let val i = !counter
      in counter := i + 1;
         i
      end

    val compare = Int.compare
end
