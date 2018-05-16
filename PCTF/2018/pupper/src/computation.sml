(* Possibly not actually a monad *)
signature COMPUTATION =
sig
    type term = Language.term
    type assignable = Assignable.assignable
    type store = term Assignable.Store.store
    type 'a t

    val pure : 'a -> 'a t
    val traverse : ('a -> 'b t) -> 'a list -> 'b list t
    val join : 'a t t -> 'a t

    val >>= : 'a t * ('a -> 'b t) -> 'b t
    val <$> : ('a -> 'b) * 'a t -> 'b t
    val <&> : 'a t * ('a -> 'b) -> 'b t
    val <*> : ('a -> 'b) t * 'a t -> 'b t
    val $> : unit t * 'a -> 'a t

    structure Ops : sig
        val >>= : 'a t * ('a -> 'b t) -> 'b t
        val <$> : ('a -> 'b) * 'a t -> 'b t
        val <&> : 'a t * ('a -> 'b) -> 'b t
        val <*> : ('a -> 'b) t * 'a t -> 'b t
        val $> : unit t * 'a -> 'a t
    end

    val branch : 'a t * 'a t -> bool -> 'a t (* Simulate an if statement with the given conditional *)

    val get : assignable -> term t
    val set : assignable -> term -> unit t
    val new : term -> assignable t

    val run : 'a t -> 'a * store (* Retrieve the "real" value *)
end

structure Computation :> COMPUTATION =
struct
infix 1 >>= <&> $>
infix 4 <$> <*>

type term = Language.term
open Assignable
type store = term Store.store

datatype 'a results
  = SINGLE of 'a * store (* deterministic answer *)
  | BRANCH of
    { cond : bool
    , thenCase : 'a results
    , elseCase : 'a results
    } (* branching computations give two paths *)

type 'a t = store -> 'a results

fun bind_results (f : 'a -> store -> 'b results) (results : 'a results) : 'b results =
  case results
   of SINGLE (x, store) => f x store
    | BRANCH {cond, thenCase, elseCase} =>
      BRANCH { cond = cond
             , thenCase = bind_results f thenCase
             , elseCase = bind_results f elseCase
             }

fun pure x s = SINGLE (x, s)
fun get a s = SINGLE (Store.lookup(s, a), s)
fun set a x s = SINGLE ((), Store.insert(s, a, x))
fun new x s = SINGLE (Store.insertNew(s, x))

fun branch (t1, t2) cond s =
  BRANCH { cond = cond
         , thenCase = t1 s
         , elseCase = t2 s
         }

fun run t =
  let val rec collapse =
       fn SINGLE result => result
        | BRANCH {cond=true, thenCase, ...} => collapse thenCase
        | BRANCH {cond=false, elseCase, ...} => collapse elseCase
  in
      collapse (t Store.empty)
  end

structure Ops =
struct
fun (t : 'a t) >>= (f : 'a -> 'b t) : 'b t = fn s => bind_results f (t s)
fun f <$> t = t >>= (pure o f)
fun t <&> f = f <$> t
fun t $> x = t <&> (fn () => x)
fun f <*> x = f >>= (fn f => f <$> x)
end

open Ops

fun curry f x y = f (x, y)

fun traverse _ nil = pure nil
  | traverse f (x::xs) = curry op:: <$> (f x) <*> (traverse f xs)

fun join t = t >>= (fn x => x)

end
