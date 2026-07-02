from kryoset.api.routes import web


def test_csp_blocks_inline_javascript(client):
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp


def test_app_uses_external_script_and_no_inline_handlers(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert '<script defer="" src="/static/app.js"></script>' in html or '<script src="/static/app.js" defer></script>' in html
    assert "onclick=" not in html
    assert "onchange=" not in html


def test_static_asset_path_traversal_is_rejected(client):
    response = client.get("/static/../app.py")
    assert response.status_code == 404


def test_static_javascript_is_served(client):
    response = client.get("/static/app.js")
    assert response.status_code == 200
    assert "dispatchDataAction" in response.text


def test_privacy_page_is_served(client):
    response = client.get("/privacy")
    assert response.status_code == 200
    assert "Information confidentialité Kryoset" in response.text


def test_csp_blocks_inline_styles(client):
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "style-src 'self' https://fonts.googleapis.com" in csp
    assert "style-src 'self' 'unsafe-inline'" not in csp


def test_static_pages_do_not_use_inline_styles(client):
    for path in ("/", "/share/example-token", "/privacy"):
        response = client.get(path)
        assert response.status_code == 200
        assert "style=" not in response.text
