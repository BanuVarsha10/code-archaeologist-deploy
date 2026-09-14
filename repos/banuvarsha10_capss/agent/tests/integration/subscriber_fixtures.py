"""
tests/integration/subscriber_fixtures.py

TEST-ONLY substitute for Systems' SubscriberValidator, which requires a
live MongoDB/Open5GS instance (mongodb://localhost:27017/, db "open5gs",
collection "subscribers") with no local fallback.

This file NEVER modifies systems/pre_amf/validators/subscriber_validator.py.
It monkey-patches the class at runtime, in test/demo code only. In a real
deployment with Open5GS/MongoDB running, this patch is not applied and
Systems' real subscriber_validator.py works completely unmodified.
"""

from contextlib import contextmanager

from systems.pre_amf.validators.subscriber_validator import SubscriberValidator


@contextmanager
def mock_subscriber_database(known_imsis: set[str]):
    """
    Temporarily replaces SubscriberValidator's MongoDB-backed
    subscriber_exists() with an in-memory allow-list, for the duration
    of the `with` block only. Restores the real implementation on exit,
    so this can never leak into unrelated tests or production use.
    """

    original_init = SubscriberValidator.__init__
    original_exists = SubscriberValidator.subscriber_exists

    def patched_init(self):
        pass  # skip real MongoClient() connection setup

    def patched_exists(self, ue_id: str) -> bool:
        imsi = ue_id.replace("imsi-", "")
        return imsi in known_imsis

    SubscriberValidator.__init__ = patched_init
    SubscriberValidator.subscriber_exists = patched_exists

    try:
        yield
    finally:
        SubscriberValidator.__init__ = original_init
        SubscriberValidator.subscriber_exists = original_exists
