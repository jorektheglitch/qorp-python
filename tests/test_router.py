import logging
from secrets import randbits

from qorp.addresses import ExternalAddress, PubkeyView
from qorp.core import Router
from qorp.core import log as core_log
from qorp.crypto import Ed25519PrivateKey
from qorp.packets import Data, RouteError, SignedRouteRequest, SignedRouteResponse
from qorp.utils.timer import Scheduler

from tests import logger
from tests.utils import EchoFrontend, PacketGenerator, NOOPFrontend, EmulatedNetworking, TracingTerminal
from tests.utils import RouteID


core_log.setLevel(logging.DEBUG)
core_log.addHandler(logging.StreamHandler())


class TestRouter:
    def test_hop_count_based_drop(self,
                                  emulated_networking: EmulatedNetworking,
                                  noop_frontend: NOOPFrontend,
                                  scheduler: Scheduler,
                                  packet_generator: PacketGenerator,
                                  ) -> None:
        """
        Router should drop RouteRequsets and RouteResponses with hop count greater or equal to max hop count.
        """

        router = Router(network=emulated_networking, scheduler=scheduler)
        terminal = TracingTerminal(router=router, frontend=noop_frontend)
        origin = ExternalAddress(Ed25519PrivateKey.generate().public_key())
        high_hop_count_rreq, _, _ = packet_generator.create_rreq(
            destination=terminal.address,
            max_hop_count=1,
            hop_count=1,
        )
        high_hop_count_rrep, _, _ = packet_generator.create_rrep(
            destination=terminal.address,
            max_hop_count=1,
            hop_count=1,
        )
        router.network_tx.send(origin=origin, packet=high_hop_count_rreq).result()
        router.network_tx.send(origin=origin, packet=high_hop_count_rrep).result()

        assert (origin, high_hop_count_rreq) not in terminal.received.from_router, \
            "Router did not drop RouteRequest with hop_count >= max_hop_count"
        assert (origin, high_hop_count_rrep) not in terminal.received.from_router, \
            "Router did not drop RouteResponse with hop_count >= max_hop_count"

    def test_rreq_rrep_drop_on_established_route(
            self,
            emulated_networking: EmulatedNetworking,
            scheduler: Scheduler,
            packet_generator: PacketGenerator,
    ) -> None:
        """
        Router should drop RouteRequsets and RouteResponses for established route.
        """

        router = Router(network=emulated_networking, scheduler=scheduler)
        source_node = emulated_networking.add_node(packet_generator=packet_generator)
        destination_node = emulated_networking.add_node(packet_generator=packet_generator)

        source_node.establish_transit_session(destination=destination_node, via_router=router)
        request, _ = emulated_networking.propagated[0]
        response, _ = emulated_networking.received[0]
        if not (isinstance(request, SignedRouteRequest) and isinstance(response, SignedRouteResponse)):
            raise RuntimeError
        router.network_tx.send(ExternalAddress(Ed25519PrivateKey.generate().public_key()), request)
        router.network_tx.send(ExternalAddress(Ed25519PrivateKey.generate().public_key()), response)
        request_received_count = 0
        response_received_count = 0
        for packet, _ in emulated_networking.propagated:
            if packet == request:
                request_received_count += 1
        for packet, _ in emulated_networking.received:
            if packet == response:
                response_received_count += 1

        assert request_received_count == 1, \
            "RouteRequest was not dropped"
        assert response_received_count == 1, \
            "RouteResponse was not dropped"

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

    def test_route_error_emit(self,
                              emulated_networking: EmulatedNetworking,
                              scheduler: Scheduler,
                              packet_generator: PacketGenerator,
                              ) -> None:
        """
        Router should send RouteError message if not route exists for incoming Data packet.
        """
        router = Router(network=emulated_networking, scheduler=scheduler)
        other_router = Router(network=emulated_networking, scheduler=scheduler)
        source_node = emulated_networking.add_node(packet_generator=packet_generator)
        destination_node = emulated_networking.add_node(packet_generator=packet_generator)

        session = source_node.establish_transit_session(destination=destination_node, via_router=other_router)
        data = session.create_outgoing_packet(b"\xFF")
        backward_data = session.reverse.create_outgoing_packet(b"\xFF")
        router.network_tx.send(source_node.origin_address, data).result()
        router.network_tx.send(destination_node.origin_address, backward_data).result()

        logger.info("\n".join(("Transieved packets:", *map(str, emulated_networking.received))))
        rerrs = [
            (packet, destination)
            for packet, destination in emulated_networking.received
            if isinstance(packet, RouteError)
        ]

        for _, destination in rerrs:
            if destination == source_node.origin_address:
                break
        else:
            raise AssertionError

        for _, destination in rerrs:
            if destination == destination_node.origin_address:
                break
        else:
            raise AssertionError
