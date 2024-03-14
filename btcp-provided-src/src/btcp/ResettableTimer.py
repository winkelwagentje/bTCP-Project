from threading import Timer, Event
import time


class ResettableTimer:
    def __init__(self, timeout, callback):
        self.timeout = timeout
        self.callback = callback
        self.timer = Timer(timeout, callback)
        self.timer_stopped = Event()

    def start(self):
        self.timer.start()

    def reset(self):
        if self.timer is not None:
            self.timer.cancel()
        self.start()

    def stop(self):
        if self.timer is not None:
            self.timer.cancel()
        self.timer_stopped.set()

    def is_stopped(self):
        return self.timer_stopped.is_set()

# Example usage:
def timeout_callback():
    print("Timeout occurred")

timer = ResettableTimer(5, timeout_callback)
timer.start()

# Do some work here...
print("presleep")
time.sleep(6)
print("postsleep")

# Reset the timer
print("about to reset")
timer.reset()
print("reset")

# Stop the timer
# timer.stop()
print("prestop")
timer.stop()
print("stopped")
