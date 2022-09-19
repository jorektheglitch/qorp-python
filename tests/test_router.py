from unittest import TestCase

from qorp.codecs import CHACHA_NONCE_LENGTH, DEFAULT_CODEC
from qorp.messages import NetworkData
from qorp.nodes import Neighbour
from qorp.router import Router
from qorp.encryption import Ed25519PrivateKey

from tests.utils import RecorderFrontend, TestConnection, TestProtocol
from tests.utils import NeignbourMock, RouterMock


class TestMessagesForwarder(TestCase):

    def setUp(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        self.router = RouterMock(private_key, frontend_factory=RecorderFrontend)
        self.forwarder = self.router.forwarder

    def test_networkdata_forwarding(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        self.forwarder.routes[(source, destination)] = (source, destination)
        self.forwarder.routes[(source, self.router)] = (source, self.router)
        nonce = b"\x00"*CHACHA_NONCE_LENGTH
        destinations = destination, self.router
        signed = [
            NetworkData(source, dst, nonce, 1, b"\x00")
            for dst in destinations
        ]
        unsigned = [
            NetworkData(source, dst, nonce, 1, b"\x01")
            for dst in destinations
        ]
        for msg in signed:
            msg.sign(source.private_key)
            self.forwarder.message_callback(source, msg)
            self.assertIn(msg, msg.destination.received)
        for msg in unsigned:
            self.forwarder.message_callback(source, msg)
            self.assertNotIn(msg, msg.destination.received)
