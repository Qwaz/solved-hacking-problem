# Code Golf

*Code Golf* is a problem about writing a short [Haskell](https://www.haskell.org/) code. We have to write a function `g`, which takes a list of strings as an argument and returns a single string. The given strings have a few holes in them, such as `"ha  m"` and `"ck m"`. Function `g` needs to find offsets for each strings, overlay them, and return it.

The rules for the correct answer are as follows:

1. The correct offset will never cause two characters to occupy the same column.
2. The correct offset will minimize the length of the final text after trimming leading and trailing spaces.
3. If there are multiple possible decryptions that follow the above rules, the lexicographically first one is correct.
4. The length of the answer code should not exceed 181 bytes.

According to the rules, the answer for `["ha  m", "ck m"]` is `"hackme"`.

This is our 176 bytes solution for the problem.

```haskell
' '?y=y
x?' '=x
_?_='~'
(x:c)??(y:d)=x?y:c??d
x??y=x++y
""#[]=[(0,"")]
x#y=[(c+1,a:d)|a:b<-[x],a/='~',(c,d)<-b#y]++[c|a:b<-[y],c<-x??a#b]
g a=snd$minimum$(#)""=<<permutations a
```

We defined four functions, `?`, `??`, `#`, and `g`.

`?` is a character overlay function. If one of them is a blank character, it will return the other character. Otherwise, it will return `~`. Here, tilde has no special meaning and is used as a placeholder.

`??` is a string overlay function. It compares the characters in two strings one by one and overlay them with function `?`. If one of them is shorter then the other one, it will concat the rest of the string to the result.

`#` defines the main algorithm. It takes two arguments `a` and `b`. `a` is the remaining suffix and `b` is the list of remaining strings. Its return value is the list of all possible non-overlapping overlay result as a pair, whose first value is the length of a string and the second value is the string. We utilized Haskell list comprehension to perform pattern matching and condition check at once.

Finally, function `g` plugs in all possible permutations of the input strings to `#`, finds the shortest and lexicographically first answer, and return it.

