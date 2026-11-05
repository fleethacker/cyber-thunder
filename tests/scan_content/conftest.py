import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.inventory.targets import Target


@pytest.fixture
def ctx(state_dir):
    context = AppContext(Settings.from_env(state_dir=state_dir, llm_backend="template",
                                          explain_precompute=False, auto_propose=False))
    context.inventory.add(Target(id="host", name="Host", asset_type="linux", transport="fixture"))
    context.inventory.save()
    yield context
    assert context.audit.verify().ok
    context.store.close()
