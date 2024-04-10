# Tests for QORP

## Unittests

### Testcases for Router

#### RouteRequest packet processing

- drop if hop_count > max_hop_count
- drop if route already established
- propagate to Networking
- send to Terminal
- do not propagate if request is not first seen
- do not send to Terminal if not first seen
- disappear after timeout exceeds

#### RouteResponse packet processing

- drop if hop_count > max_hop_count
- drop response for unknown request
- drop if route already established
- both route and reverse route added
- propagate to all directions where request comes from

#### RouteError packet processing

- drop if origin is not on route
- both route and reverse route removed
- send on the reverse route
- emit if link was broken

#### Data packet processing

- pass to Terminal
- pass to Networking
- emit RouteError if no route
- drop packet if origin is not prev_hop

#### General

- Terminal attach/detach

### Testcases for Terminal

- #TODO
