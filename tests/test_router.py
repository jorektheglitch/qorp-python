import logging

from qorp.core import Router
from qorp.core import log as core_log
from qorp.utils.timer import Scheduler

from tests.utils import PacketGenerator, EmulatedNetworking


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
