signature ASSIGNABLE =
sig
    eqtype assignable
    structure Store :
              sig
                  type 'a store
                  val empty : 'a store
                  val lookup : 'a store * assignable -> 'a
                  val insert : 'a store * assignable * 'a -> 'a store
                  val insertNew : 'a store * 'a -> assignable * 'a store
              end
end

structure Assignable :> ASSIGNABLE =
struct
type assignable = int

structure Store =
struct
structure Map = IntRedBlackMap
type 'a store = 'a Map.map * int (* What's the next unused assignable? *)
val empty = (Map.empty, 0)
fun lookup ((map, _), a) = Map.lookup(map, a)
fun insert ((map, ap), a, x) = (Map.insert(map, a, x), ap)
fun insertNew ((map, ap), x) = (ap, (Map.insert(map, ap, x), ap + 1))
end
end
