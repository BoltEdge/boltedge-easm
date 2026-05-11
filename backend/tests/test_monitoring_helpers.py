from app.monitoring.helpers import should_alert_on_recurrence


class _Org:
    def __init__(self, default): self.alert_on_recurrence = default


class _Monitor:
    def __init__(self, override): self.alert_on_recurrence_override = override


def test_inherits_org_default_when_override_null():
    assert should_alert_on_recurrence(_Monitor(None), _Org(True))  is True
    assert should_alert_on_recurrence(_Monitor(None), _Org(False)) is False


def test_explicit_true_override_wins_over_org_false():
    assert should_alert_on_recurrence(_Monitor(True), _Org(False)) is True


def test_explicit_false_override_wins_over_org_true():
    assert should_alert_on_recurrence(_Monitor(False), _Org(True)) is False
