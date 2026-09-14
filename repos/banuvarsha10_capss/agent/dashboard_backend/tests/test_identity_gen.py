from dashboard_backend.identity_gen import generate_fresh_identities, mask_identity


def test_generates_requested_count():
    identities = generate_fresh_identities(20)
    assert len(identities) == 20


def test_identities_are_mutually_unique_within_one_call():
    identities = generate_fresh_identities(50)
    ue_ids = {i.ue_id for i in identities}
    sucis = {i.suci for i in identities}
    assert len(ue_ids) == 50
    assert len(sucis) == 50


def test_repeated_calls_never_collide():
    """Freshness across runs — required for the cold-start/RAG demo story."""
    first = {i.ue_id for i in generate_fresh_identities(30)}
    second = {i.ue_id for i in generate_fresh_identities(30)}
    assert first.isdisjoint(second)


def test_identity_format_matches_project_convention():
    ident = generate_fresh_identities(1)[0]
    assert ident.ue_id.startswith("imsi-99970")
    assert len(ident.ue_id) == len("imsi-") + 15  # MCC(3) + MNC(2) + MSIN(10)
    assert ident.suci.startswith("suci-0-999-70-0000-0-0-")
    assert ident.suci.endswith(ident.msin)


def test_mask_identity_partially_masks():
    masked = mask_identity("imsi-999700000000001")
    assert masked != "imsi-999700000000001"
    assert masked.startswith("imsi-99970")
    assert masked.endswith("001")
    assert "*" in masked
