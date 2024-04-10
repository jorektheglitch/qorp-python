from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, Iterator, TypeVar


T = TypeVar("T")
KT = TypeVar("KT")
VT = TypeVar("VT", covariant=True)


class NestedMappingProxy(Mapping[T, MappingProxyType[KT, VT]]):
    def __init__(self, mapping: Mapping[T, Mapping[KT, VT]]) -> None:
        super().__init__()
        self.__origin__ = mapping

    def __getitem__(self, __key: T) -> MappingProxyType[KT, VT]:
        item = self.__origin__[__key]
        return MappingProxyType(item)

    def __iter__(self) -> Iterator[T]:
        return iter(self.__origin__)

    def __len__(self) -> int:
        return super().__len__()
