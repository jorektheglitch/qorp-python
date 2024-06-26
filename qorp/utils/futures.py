from concurrent.futures import Future
from typing import Any, Callable, TypeVar

from .timer import Scheduler, ScheduleHandle


T = TypeVar("T")


class ConstFuture(Future[T]):
    def __init__(self, *, result: T) -> None:
        super().__init__()
        self.set_result(result)


class RaisesFuture(Future[Any]):  # type: ignore
    def __init__(self, *, exc: Exception) -> None:
        super().__init__()
        self.set_exception(exc)


def set_ttl(
    scheduler: Scheduler,
    ttl: float,
    future: Future[T],
    callback: Callable[[Future[T]], None] | None = None
) -> ScheduleHandle:

    def kill() -> None:
        if future.done():
            return
        if callback is not None:
            callback(future)
        future.set_exception(
            TimeoutError(f"Future {future} killed due to TTL expiration.")
        )

    handle = scheduler.call_later(ttl, kill)
    return handle
