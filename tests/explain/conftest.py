"""Keep explanation unit tests independent of credentials and network access."""
import os
import socket

import pytest


@pytest.fixture(autouse=True)
def isolated_model_environment(monkeypatch, request):
    live_model_test = (
        request.node.path.name == "test_service.py"
        and request.node.name == "test_real_local_model"
        and os.environ.get("CT_TEST_LLM") == "1"
    )
    if live_model_test:
        return  # Only the explicitly opted-in integration test inherits credentials and network access.

    monkeypatch.delenv("CT_LLM_API_KEY", raising=False)

    def no_network(*args, **kwargs):
        pytest.fail("Network access is disabled for explanation unit tests; mock the transport")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", no_network)
