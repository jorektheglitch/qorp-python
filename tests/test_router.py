import logging

from qorp.addresses import PubkeyView
from qorp.core import Router
from qorp.core import log as core_log
from qorp.packets import Data
from qorp.utils.timer import Scheduler

from tests.utils import EchoFrontend, PacketGenerator, EmulatedNetworking, TracingTerminal


core_log.setLevel(logging.DEBUG)
core_log.addHandler(logging.StreamHandler())


class TestRouter:
    def test_sunny_case_transit_route_establishment(
            self,
            packet_generator: PacketGenerator,
            emulated_networking: EmulatedNetworking,
            scheduler: Scheduler,
    ) -> None:
        router = Router(network=emulated_networking, scheduler=scheduler)
        source_node = emulated_networking.add_node(packet_generator=packet_generator)
        destination_node = emulated_networking.add_node(packet_generator=packet_generator)

        session = source_node.establish_transit_session(destination=destination_node, via_router=router)

        data = session.create_outgoing_packet(b"\xFF")
        backward_data = session.reverse.create_outgoing_packet(b"\xFF")
        router.network_tx.send(source_node.origin_address, data).result()
        router.network_tx.send(destination_node.origin_address, backward_data).result()

        assert (data, destination_node.origin_address) in emulated_networking.received, \
            "Data was not sent via forward route"
        assert (backward_data, source_node.origin_address) in emulated_networking.received, \
            "Data was not sent via backward route"

    def test_sunny_case_route_establishment(
            self,
            emulated_networking: EmulatedNetworking,
            echo_frontend: EchoFrontend,
            scheduler: Scheduler,
            packet_generator: PacketGenerator,
    ) -> None:
        router = Router(network=emulated_networking, scheduler=scheduler)
        terminal = TracingTerminal(router=router, frontend=echo_frontend)
        remote_node = emulated_networking.add_node(packet_generator=packet_generator)

        session = remote_node.establish_session(
            destination=terminal.address, via_router=router,
        )
        data = session.create_outgoing_packet(b"\xFF")
        router.network_tx.send(remote_node.origin_address, data).result()

        assert (remote_node.origin_address, data) in terminal.received.from_router, \
            "Data was not received by Terminal"

        for packet, destination in emulated_networking.received:
            if isinstance(packet, Data) and destination == remote_node.origin_address:
                break
        else:
            print("Networking receive packets:\n  ",
                  "\n  ".join(f"From {PubkeyView(origin)} packet {packet}"
                              for packet, origin in emulated_networking.received),
                  )
            assert False, \
                f"Data was not sent back from {PubkeyView(terminal.full_address)}"
