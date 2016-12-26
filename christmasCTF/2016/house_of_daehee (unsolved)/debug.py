import gdb


class AgainCommand(gdb.Command):
    def __init__(self):
        super(AgainCommand, self).__init__(
            "again",
            gdb.COMMAND_RUNNING
        )

    def invoke(self, arg, from_tty):
        gdb.execute('tbreak *unlink+173')  # b
        gdb.execute('tbreak *main+807')  # c
        gdb.execute('tbreak *main+825')  # b
        gdb.execute('tbreak *main+843')  # a

        f = open('payload', 'w')
        f.write('12345678\xa1')
        f.close()

        gdb.execute('run < payload')


class QuickViewCommand(gdb.Command):
    def __init__(self):
        super(QuickViewCommand, self).__init__(
            "qv",
            gdb.COMMAND_DATA
        )

    def invoke(self, arg, from_tty):
        gdb.execute('x/40wx 0x555555757000')

AgainCommand().invoke([], False)
QuickViewCommand()
