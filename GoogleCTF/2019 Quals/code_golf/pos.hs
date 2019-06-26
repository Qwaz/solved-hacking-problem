import Prelude
import Control.Applicative
import Control.Arrow
import Control.Monad
import Data.Array
import Data.Bits
import Data.Bool
import Data.Char
import Data.Complex
import Data.Dynamic
import Data.Either
import Data.Eq
import Data.Fixed
import Data.Function
import Data.Graph
import Data.Int
import Data.Ix
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Ratio
import Data.Tree
import Data.Tuple
import Data.Typeable
import Data.Word
import Text.Printf

' '?y=y
x?' '=x
_?_='~'
(x:c)??(y:d)=x?y:c??d
x??y=x++y
""#[]=[(0,"")]
x#y=[(c+1,a:d)|a:b<-[x],a/='~',(c,d)<-b#y]++[c|a:b<-[y],c<-x??a#b]
g a=snd$minimum$(#)""=<<permutations a

test input ans=
  let output = g input
  in do
    print ("output: " ++ output)
    print ("answer: " ++ ans)

main=do
  test ["hac m", "k e"] "hackme"
  test ["b", "a"] "ab"
  test [] ""
  test ["rst r", "rsy rsytsr", "a"] "rst rrsyarsytsr"

