"""Update continuation retains the explicit decision without freezing current authorization."""
from dataclasses import replace
import time

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.vulnerabilities import engine
from cyberthunder.security.step_up import StepUpRequired
from tests.security.job_helpers import enable_auth
from tests.security.test_sessions import advance


@pytest.mark.parametrize("revoke", [False, True])
def test_database_publication_after_freshness_window_still_checks_policy(svc, fake_download, monkeypatch, revoke):
    human = replace(enable_auth(svc.ctx, node=["admin"]), expires_at=time.time() + 1800)
    svc.ctx.settings.vulnerability_update_timeout_s = 900
    original = engine.run
    def download(*args, **kwargs):
        advance(monkeypatch, 301)
        if revoke:
            svc.ctx.access.path.write_text(svc.ctx.access.path.read_text() + "\n")
        return original(*args, **kwargs)
    monkeypatch.setattr(engine, "run", download)
    with principal_scope(human):
        job = svc.update(actor=human.actor, include_java=False, background=False)
    assert job["state"] == ("stopped" if revoke else "completed"), job
    assert bool(svc._state().get("selected")) is not revoke
    with principal_scope(human), pytest.raises(StepUpRequired):
        svc.save_settings({"expected_revision": 0}, actor=human.actor)
