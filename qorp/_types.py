import sys
from typing import NewType

if sys.version_info < (3, 12):
    Buffer = memoryview | bytearray | bytes
else:
    from collections.abc import Buffer

RouteID = NewType("RouteID", int)
