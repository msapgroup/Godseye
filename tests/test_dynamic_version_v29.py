from pathlib import Path

from app import main


def test_runtime_version_matches_release_file():
    expected = (Path(main.BASE_DIR) / "VERSION").read_text(encoding="utf-8").strip()
    assert expected
    assert main.APP_VERSION == expected


def test_login_footer_uses_runtime_release_version():
    html = main.dashboard().body.decode("utf-8")
    assert f"GODSEYE v{main.APP_VERSION}" in html
    assert "__APP_VERSION__" not in html
    assert "GODSEYE v2.7.0" not in html


def test_login_template_is_not_hardcoded_to_release_number():
    source = Path(main.__file__).read_text(encoding="utf-8")
    assert 'GODSEYE v__APP_VERSION__' in source
    assert 'html = html.replace("__APP_VERSION__", APP_VERSION)' in source
