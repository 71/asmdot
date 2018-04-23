
class Binder():

    def __init__(self):
        self._arch = ''
        self._opts = None

    @property
    def arch(self):
        return self._arch

    @property
    def options(self):
        return self._opts
    
    def change_arch(self, arch):
        self._arch = arch
    
    def define(self, name, params):
        pass

class OutputBinder(Binder):

    def __init__(self):
        self.output = None

    def change_arch(self, arch):
        super().change_arch(arch)

        binder = self

        class EnterLeaveNotifier():
            def __enter__(self):
                binder.enter(arch)

            def __exit__(self, type, value, traceback):
                binder.leave(arch)
        
        return EnterLeaveNotifier()
    
    def enter(self, arch):
        pass

    def leave(self, arch):
        pass
