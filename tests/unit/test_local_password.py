from app.core.local_password import hash_password, verify_password


def test_hash_verifies_only_the_right_password_and_is_salted():
    h = hash_password("Example-Passw0rd!")
    assert h.startswith("scrypt$") and "Example-Passw0rd!" not in h
    assert verify_password("Example-Passw0rd!", h)
    assert not verify_password("admin@123", h)
    assert hash_password("Example-Passw0rd!") != h  # fresh salt each time


def test_missing_or_malformed_hashes_never_verify():
    assert not verify_password("x", None)
    assert not verify_password("x", "")
    assert not verify_password("x", "plain-text")
    assert not verify_password("x", "scrypt$1$2$3$bad$bad")
