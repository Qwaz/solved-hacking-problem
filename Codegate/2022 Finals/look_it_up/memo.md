Start: LHS = RHS = 1

`for i in 0..n`
$$
\begin{align}
LHS &= (LHS * (\beta + 1)) \\
mul &= \gamma * (\beta + 1) + \beta * t[i+1] + t[i] \\
LHS &= LHS * mul * (\gamma + f[i]) \\
\end{align}
$$

$$
\begin{align}
mul1 &= \gamma * (\beta + 1) + \beta * s1[i+1] + s1[i] \\
mul2 &= \gamma * (\beta + 1) + \beta * s2[i+1] + s2[i] \\
RHS &= RHS * mul1 * mul2
\end{align}
$$

When n = 1
$$
\begin{align}
LHS &= (\beta + 1) * (\gamma * (\beta + 1) + \beta * t[1] + t[0]) * (\gamma + f[0]) \\
RHS &= (\gamma * (\beta + 1) + \beta * s1[1] + s1[0]) * (\gamma * (\beta + 1) + \beta * s2[1] + s2[0])
\end{align}
$$
If we set all elements the same
$$
((\gamma + s1) * (\beta + 1)) ^ n \\
((\gamma + s2) * (\beta + 1)) ^ n \\
(\beta + 1) ^ n \\
((\gamma + t) * (\beta + 1)) ^ n \\
\Pi_{i=0..n} (\gamma + f[i])
$$


