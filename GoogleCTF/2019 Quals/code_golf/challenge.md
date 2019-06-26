We've broken into a communications system and intercepted transparencies with
what appears to be gibberish written on them; our cryptographers indicate that
the transparencies seem to form a sort of cipher. In fact, it seems possible to
recover the original unscrambled text by overlaying the transparencies and
offsetting them by an appropriate amount.

For example, given the strings `"ha  m"` and `"ck e"`:

If you overlay them:

    "ha  m" 
    "ck e" 

Shift them by an appropriate offset:

    "ha  m" 
      "ck e"

And combine them, you get `"hackme"`.

For the data we're working with, the following rules seem to always hold:

1. The correct offset will never cause two characters to occupy the same column.
2. The correct offset will minimize the length of the final text after trimming
   leading and trailing spaces.
3. If there are multiple possible decryptions that follow the above rules, the
   lexicographically first one is correct.

Your task is to write a payload that decrypts these messages for us.
Unfortunately, the communications system has a rather unusual environment: its
machines have custom-built processors that interpret Haskell natively, meaning
that we'll need you to write your payload in Haskell, not assembly.

To make matters worse, we only have a limited number of bytes in our payload:
your solution may contain at most 181 bytes of Haskell code.

Even more bizarrely, your solution must be provided in a single line of 
Base64-encoded UTF-8, without any extra whitespace. That is, if your code
looked like this:

    g a = "This is probably not the right answer"

You would need to submit:

    ZyBhID0gIlRoaXMgaXMgcHJvYmFibHkgbm90IHRoZSByaWdodCBhbnN3ZXIi

Note that it is the length of your source code, *not* of the Base64 version,
that matters. The above example would count as 46 bytes.


Tip: On a machine with OpenSSL installed, you can pipe a string to
`openssl base64`, then `paste -sd "" -` to convert it to Base64 without 
newlines. Alternatively, if your machine has it available, you can just
pipe the string to `base64 -w 0`.


More specifically, your task is to write a function `g :: [String] -> String`
that takes a list of strings, each representing a transparency, and produces a
decrypted string according to the rules above. You may write any helper
functions you need, so long as the total length of your code does not exceed 181
bytes.

You have access to the following modules, all of which are imported for you.
No other modules may be imported.

    Prelude
    Control.Applicative
    Control.Arrow
    Control.Monad
    Data.Array
    Data.Bits
    Data.Bool
    Data.Char
    Data.Complex
    Data.Dynamic
    Data.Either
    Data.Eq
    Data.Fixed
    Data.Function
    Data.Graph
    Data.Int
    Data.Ix
    Data.List
    Data.Maybe
    Data.Monoid
    Data.Ord
    Data.Ratio
    Data.Tree
    Data.Tuple
    Data.Typeable
    Data.Word
    Debug.SimpleReflect
    Text.Printf
    ShowFun