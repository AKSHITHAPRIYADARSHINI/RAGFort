from backend.app.auth.session import LocalOidcSessionStore


def test_server_side_browser_session_preserves_and_revokes_epoch() -> None:
    store = LocalOidcSessionStore()
    session_id = store.create("signed-token", expires_in=60, authorization_epoch=3)

    assert store.token(session_id) == "signed-token"
    assert store.epoch(session_id) == 3

    store.revoke(session_id)

    assert store.token(session_id) is None
    assert store.epoch(session_id) is None
