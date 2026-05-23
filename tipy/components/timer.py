from __future__ import annotations

from time import monotonic
from heapq import heappush, heappop
from threading import Thread, Condition

from tipy.lib.logger import log

from typing import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core


class TimerTask:
    def __init__(self,
                 *,
                 expire_after,
                 remove_at_execute: bool,
                 call: Callable,
                 name: str =''
                 ):

        self._expire_after = expire_after
        self._start_time = monotonic()
        self._call: Callable = call
        self._deleted = False
        self.name = name

        self.remove_at_execute = remove_at_execute
        self.retry_counter: int = 0

    def execute_at(self):
        return self._start_time + self._expire_after

    def execute(self):
        if not self._deleted:
            self._call()

        if __debug__:
            log(
                "timer",
                f"timer fired: {self.name or 'unnamed'}",
                level="DEBUG"
            )

    def remove(self):
        """
        Mark this task to indicate that its absolute
        """
        self._deleted = True


class Timer:
    def __init__(self, core: Core | None = None):
        self._tasks: list[tuple[float, TimerTask]] = []
        self._stop_thread: bool = False
        self._cond: Condition = Condition()

    def start(self):
        Thread(target=self._timer_loop, daemon=True).start()

    def shutdown(self):
        with self._cond:
            self._stop_thread = True
            self._cond.notify_all()
        if __debug__:
            log(
                "stack",
                "Timer shutdown",
                level="INFO"
            )

    def _timer_loop(self):
        if __debug__:
            log(
                "stack",
                "Timer started",
                level="INFO"
            )

        while not self._stop_thread:
            ready_tasks: list[TimerTask] = []

            with self._cond:

                if not self._tasks:
                    self._cond.wait()
                    continue

                now = monotonic()

                while self._tasks and self._tasks[0][0] <= now:
                    task = heappop(self._tasks)
                    ready_tasks.append(task[1])

            for t in ready_tasks:
                t.execute()

            with self._cond:
                if self._tasks:
                    timeout = max(0, self._tasks[0][0] - now)
                else:
                    timeout = None

                self._cond.wait(timeout=timeout)

    def schedule_timer(self, expire_after,
                       remove_at_execute,
                       call: Callable,
                       timer_name: str = ''):

        task = TimerTask(
            expire_after=expire_after,
            remove_at_execute=remove_at_execute,
            call=call,
            name=timer_name
        )

        with self._cond:
            heappush(
                self._tasks,
                (task.execute_at(), task)
            )
            if __debug__:
                log(
                    "timer",
                    f"timer scheduled: {timer_name or 'unnamed'} (expires in {expire_after}s)",
                    level="DEBUG"
                )
            self._cond.notify()

        return task
