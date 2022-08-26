import asyncio
from asyncio import Future
from contextlib import contextmanager

from typing import Callable, Dict, Optional, Set

from .encryption import X25519PrivateKey, X25519PublicKey
from .frontend import Frontend
from .messages import Message
from .messages import Data, RouteRequest, RouteResponse, RouteError
from .nodes import Node, Neighbour
from .transports import Listener


RREQ_TIMEOUT = 10


class Router(Node):

    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    broadcast_listeners: Set[Listener]
    frontend: Frontend
    neighbours: Set[Neighbour]
    directions: Dict[Node, Neighbour]
    pending_requests: Dict[Node, Set["Future[Neighbour]"]]

    async def find_direction(self, target: Node, timeout: Optional[float] = RREQ_TIMEOUT) -> Neighbour:
        if target in self.directions:
            return self.directions[target]
        request = RouteRequest(self, target)
        with self._track_request(target) as future:
            for neighbour in self.neighbours:
                neighbour.send(request)
            response = await asyncio.wait_for(future, timeout)
        return response

    @contextmanager
    def _track_request(self, target: Node):
        future: Future[Neighbour] = Future()
        requests = self.pending_requests.setdefault(target, set())
        requests.add(future)
        try:
            yield future
        finally:
            requests.remove(future)

    def network_message_callback(self, source: Neighbour, message: Message):
        direction: Optional[Neighbour]
        if isinstance(message, Data):
            target = message.destination
            if target == self:
                self.frontend.send(message)
            elif target in self.directions:
                direction = self.directions[target]
                direction.send(message)
            else:
                rerr = RouteError(self, source)
                source.send(rerr)
        elif isinstance(message, RouteRequest):
            target = message.destination
            requests = self.pending_requests.setdefault(target, set())
            future: Future[Neighbour] = Future()
            future.add_done_callback(self._done_request(target))
            # TODO: resend RouteRequest to all neighbours except source
            requests.add(future)
        elif isinstance(message, RouteResponse):
            target = message.destination
            direction = self.directions.get(target)
            if direction is not None:
                direction.send(message)
        elif isinstance(message, RouteError):
            # TODO: remove direction from directions
            pass
        else:
            raise TypeError

    def frontend_message_callback(self, message: Data):
        # TODO: write frontend-originated data message processing code
        pass

    def _done_request(self, target: Node) -> Callable[["Future[Neighbour]"], None]:
        def callback(future: "Future[Neighbour]"):
            futures = self.pending_requests.get(target)
            if futures and future in futures:
                futures.remove(future)
                if future.done() and not future.cancelled():
                    direction = future.result()
                    for future in futures:
                        future.set_result(direction)
        return callback
