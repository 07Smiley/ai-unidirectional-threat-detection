from src.response.policy import ThreatResponsePolicy


def test_threshold_only_offers_action():
    policy = ThreatResponsePolicy(threshold=0.75)
    assert not policy.requires_user_confirmation(0.749)
    assert policy.requires_user_confirmation(0.75)
    assert policy.requires_user_confirmation(0.90)
