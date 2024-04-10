from __future__ import annotations

from abc import abstractmethod
from typing import Any, Callable, Protocol, TypeVarTuple

Ts = TypeVarTuple("Ts")
Callback = Callable[[*Ts], Any]  # type: ignore


class Timer(Protocol):
    @abstractmethod
    def call_later(self, delay: float, callback: Callback[*Ts], *args: *Ts) -> TimerHandle:
        pass


class TimerHandle(Protocol):
    @abstractmethod
    def cancel(self) -> None:
        pass

    @abstractmethod
    def cancelled(self) -> bool:
        pass
