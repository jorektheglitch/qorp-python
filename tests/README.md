# Tests for QORP

## Unittests

### Testcases for Router

#### RouteRequest packet processing

- [x] drop if hop_count > max_hop_count (test_hop_count_based_drop)
- [x] drop if route already established (test_rreq_rrep_drop_on_established_route)
- [x] propagate to Networking (test_sunny_case_transit_route_establishment)
- [x] send to Terminal (test_sunny_case_route_establishment)
- [ ] do not propagate if request is not first seen
- [ ] do not send to Terminal if not first seen
- [ ] disappear after timeout exceeds

#### RouteResponse packet processing

- [x] drop if hop_count > max_hop_count (test_hop_count_based_drop)
- [x] drop if route already established (test_rreq_rrep_drop_on_established_route)
- [ ] drop response for unknown request
- [x] both route and reverse route added (test_sunny_case_transit_route_establishment, test_sunny_case_route_establishment)
- [ ] propagate to all directions where request comes from

#### RouteError packet processing

- [ ] drop if origin is not on route
- [ ] both route and reverse route removed
- [ ] send on the reverse route
- [ ] emit if link was broken

#### Data packet processing

- [x] pass to Terminal (test_sunny_case_route_establishment)
- [x] pass to Networking (test_sunny_case_transit_route_establishment)
- [ ] emit RouteError if no route
- [ ] drop packet if origin is not prev_hop

#### General

- [ ] Terminal attach/detach

### Testcases for Terminal

- #TODO
