"""Tests for aegis.bus: subscribe/publish/unsubscribe semantics."""

from aegis.bus import Bus, default_bus


def test_publish_delivers_to_all_subscribers_and_returns_count():
    bus = Bus()
    received = []
    bus.subscribe("findings", received.append)
    bus.subscribe("findings", lambda p: received.append(("echo", p)))
    delivered = bus.publish("findings", {"score": 90})
    assert delivered == 2
    assert received[0] == {"score": 90}
    assert received[1] == ("echo", {"score": 90})


def test_publish_payload_passed_through_unchanged():
    bus = Bus()
    seen = []
    bus.subscribe("cases", seen.append)
    payload = {"id": "case-1"}
    bus.publish("cases", payload)
    assert seen[0] is payload


def test_publish_with_no_subscribers_returns_zero():
    bus = Bus()
    assert bus.publish("nothing-here", {}) == 0


def test_subscribe_is_topic_scoped():
    bus = Bus()
    hits = []
    bus.subscribe("topic-a", hits.append)
    assert bus.publish("topic-b", 1) == 0
    assert hits == []
    assert bus.publish("topic-a", 1) == 1
    assert hits == [1]


def test_unsubscribe_stops_delivery():
    bus = Bus()
    received = []
    off = bus.subscribe("alerts", received.append)
    bus.publish("alerts", 1)
    off()
    bus.publish("alerts", 2)
    assert received == [1]


def test_unsubscribe_is_idempotent():
    bus = Bus()
    off = bus.subscribe("alerts", lambda p: None)
    off()
    off()  # second call must not raise (ValueError swallowed)


def test_topics_lists_subscribed_topics_sorted():
    bus = Bus()
    bus.subscribe("zeta", lambda p: None)
    bus.subscribe("alpha", lambda p: None)
    assert bus.topics() == ["alpha", "zeta"]


def test_multiple_publishes_accumulate():
    bus = Bus()
    received = []
    bus.subscribe("stream", received.append)
    bus.publish("stream", "a")
    bus.publish("stream", "b")
    assert received == ["a", "b"]


def test_default_bus_is_a_bus():
    assert isinstance(default_bus, Bus)
