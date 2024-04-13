from __future__ import annotations

from abc import abstractmethod
from typing import Any, Callable, Protocol, TypeVarTuple

Args = TypeVarTuple("Args")
Callback = Callable[[*Args], Any]  # type: ignore


class Scheduler(Protocol):
    @abstractmethod
    def call_later(self, delay: float, callback: Callback[*Args], *args: *Args) -> ScheduleHandle:
        pass


class ScheduleHandle(Protocol):
    @abstractmethod
    def cancel(self) -> None:
        pass

    @abstractmethod
    def cancelled(self) -> bool:
        pass
