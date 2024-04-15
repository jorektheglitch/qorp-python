from pytest import fixture

from tests.utils import NOOPFrontend, PacketGenerator, StoringFrontend, EmulatedNetworking, ThreadedScheduler


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
