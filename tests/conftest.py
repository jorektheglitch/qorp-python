from pytest import fixture

from tests.utils import EchoFrontend, NOOPFrontend, StoringFrontend
from tests.utils import EmulatedNetworking, PacketGenerator, ThreadedScheduler


@fixture
def echo_frontend() -> EchoFrontend:
    return EchoFrontend()


@fixture
def noop_frontend() -> NOOPFrontend:
    return NOOPFrontend()


@fixture
def storing_frontend() -> StoringFrontend:
    return StoringFrontend()


@fixture
def emulated_networking() -> EmulatedNetworking:
    return EmulatedNetworking()


@fixture
def packet_generator() -> PacketGenerator:
    return PacketGenerator()


@fixture
def scheduler() -> ThreadedScheduler:
    return ThreadedScheduler()
