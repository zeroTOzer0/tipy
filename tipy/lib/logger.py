import inspect
import time

from tipy.config.config import LOG_CHANEL

START_TIME = time.monotonic()

LEVEL = {
    "INFO": "\033[1m",
    "WARN": "\033[93m\033[1m",
    "ERROR": "\033[41m",
    "DEBUG": "\033[90m",
    "RESET": "\033[0m",
}


def _get_caller(depth: int):
    frame_info = inspect.stack()[depth]
    frame = frame_info.frame
    func = frame_info.function

    if "self" in frame.f_locals:
        cls = frame.f_locals["self"].__class__.__name__
        return f"{cls}.{func}"

    return func


def log(channel: str, message: str, level: str = "INFO", depth: int = 2):
    if channel not in LOG_CHANEL:
        return

    elapsed = time.monotonic() - START_TIME
    caller = _get_caller(depth)

    level = level.upper()
    style = LEVEL.get(level, "")
    reset = LEVEL["RESET"]

    output = (
        f"{style}"
        f"{elapsed:07.02f} | "
        f"{channel.upper():<10} | "
        f"{level:<6} | "
        f"{caller:<35} | "
        f"{message}"
        f"{reset}"
    )

    print(output)