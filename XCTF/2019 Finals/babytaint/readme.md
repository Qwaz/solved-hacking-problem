## Description

Have you ever heard of [Dynamic Taint Analysis](https://users.ece.cmu.edu/~aavgerin/papers/Oakland10.pdf) of [JavaScript](https://people.eecs.berkeley.edu/~ksen/papers/jalangi.pdf)?

In this challenge I have designed a simple dynamic taint analysis algorithm for JavaScript, which _intends_ to prevent malicious JavaScript skimmer from sending secret message from source to sink. However, writing analysis without any false negative is hard.

You may find [this document](https://github.com/Samsung/jalangi2/blob/master/docs/MyAnalysis.html) helpful.
