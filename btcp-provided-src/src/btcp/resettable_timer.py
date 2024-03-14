from threading import Timer


class ResettableTimer:
    def __init__(self, timeout, callback):
        self.timeout = timeout
        self.callback = callback
        self.timer = Timer(timeout, callback)
        self.timer_stopped = False

    def reset(self):
        self.timer.cancel()
        self.timer_stopped = False
        self.start()

    def stop(self):
        self.timer.cancel()
        self.timer_stopped = True

    def is_stopped(self):
        return self.timer_stopped