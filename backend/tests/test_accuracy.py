"""
Scanner Detection Accuracy & False Positive Prevention Tests
============================================================
Tests for:
1. Real 404 responses -> NO finding
2. Soft-404 responses (200 OK + Custom Error HTML) -> NO finding
3. Redirects to homepage (302/301 -> /) -> NO finding
4. Generic HTML 200 OK -> NO finding
5. Genuine exposed .env -> Finding with redacted evidence
6. Genuine exposed backup.sql -> Finding
7. Genuine exposed wp-config.php.bak -> Finding
8. Secret redaction verification
"""
import pytest
import httpx
from app.scanner.content_analyzer import analyze_content, _validate_content, _redact_secrets, _is_soft_404_or_redirect


@pytest.mark.asyncio
async def test_real_404_response():
    """Test 1: Real 404 response on /.env returns NO finding."""
    async with httpx.AsyncClient(base_url="http://testsite.com") as client:
        # Mock httpx using transport handler or custom mock
        pass  # We will test using respx or mock transport


@pytest.mark.asyncio
async def test_soft_404_custom_html_response():
    """Test 2: Soft 404 (200 OK + Custom 'Page Not Found' HTML) returns NO finding."""
    soft_404_html = """<!DOCTYPE html>
    <html>
    <head><title>Page Not Found - MyWebsite</title></head>
    <body>
        <h1>Oops! Page Not Found</h1>
        <p>The page you requested could not be found. Please return to homepage.</p>
    </body>
    </html>"""

    path_info = {"path": "/.env", "severity": "critical", "title": "Exposed .env File",
                 "description": "desc", "cvss": 9.8, "category": "Credential Exposure", "rec": "rec"}

    request = httpx.Request("GET", "http://testsite.com/.env")
    response = httpx.Response(200, text=soft_404_html, request=request, headers={"content-type": "text/html"})

    baseline = {
        "status_code": 200,
        "final_url_path": "/sentinelscan-nonexistent-12345",
        "content_type": "text/html",
        "body_len": len(soft_404_html),
        "body_text": soft_404_html.lower(),
        "title": "page not found - mywebsite",
        "tokens": {"page", "found", "mywebsite", "oops", "requested", "could"},
        "is_html": True,
    }

    # Must detect as soft-404 / invalid
    assert _is_soft_404_or_redirect(response, baseline, path_info) is True


@pytest.mark.asyncio
async def test_redirect_to_homepage():
    """Test 3: Redirect from /.env -> 302 -> / (Homepage) returns NO finding."""
    path_info = {"path": "/.env", "severity": "critical", "title": "Exposed .env File"}

    req_orig = httpx.Request("GET", "http://testsite.com/.env")
    res_redirect = httpx.Response(302, headers={"location": "/"}, request=req_orig)

    req_final = httpx.Request("GET", "http://testsite.com/")
    res_final = httpx.Response(200, text="<html><body>Welcome to Homepage</body></html>",
                               request=req_final, history=[res_redirect], headers={"content-type": "text/html"})

    baseline = {"status_code": 404, "final_url_path": "/sentinelscan-nonexistent", "is_html": True}

    assert _is_soft_404_or_redirect(res_final, baseline, path_info) is True


@pytest.mark.asyncio
async def test_generic_html_200():
    """Test 4: Generic HTML 200 OK page for /.env returns NO finding."""
    path_info = {"path": "/.env", "severity": "critical", "title": "Exposed .env File"}
    homepage_html = """<!DOCTYPE html>
    <html lang="en">
    <head><meta charset="utf-8"><title>My Awesome Company</title></head>
    <body><h1>Welcome to Our Store</h1><a href="/products">Shop Now</a></body>
    </html>"""

    req = httpx.Request("GET", "http://testsite.com/.env")
    res = httpx.Response(200, text=homepage_html, request=req, headers={"content-type": "text/html"})

    baseline = {"status_code": 404, "final_url_path": "/sentinelscan-nonexistent", "is_html": True}

    # Either detected as soft-404 or fails content validation
    is_soft404 = _is_soft_404_or_redirect(res, baseline, path_info)
    is_valid, _, _ = _validate_content(path_info, res)

    assert is_soft404 or not is_valid


@pytest.mark.asyncio
async def test_genuine_exposed_env():
    """Test 5: Genuine exposed .env file returns VALID finding with redacted secrets."""
    path_info = {"path": "/.env", "severity": "critical", "title": "Exposed .env File"}
    env_content = """# App Configuration
    APP_NAME=SentinelScan
    APP_ENV=production
    APP_KEY=base64:9876543210qwertyuiop=
    DB_HOST=127.0.0.1
    DB_USER=admin_user
    DB_PASSWORD=SuperSecretPass123!
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    req = httpx.Request("GET", "http://testsite.com/.env")
    res = httpx.Response(200, text=env_content, request=req, headers={"content-type": "text/plain"})

    baseline = {"status_code": 404, "final_url_path": "/sentinelscan-nonexistent", "is_html": False}

    assert _is_soft_404_or_redirect(res, baseline, path_info) is False
    is_valid, evidence, confidence = _validate_content(path_info, res)

    assert is_valid is True
    assert confidence == "high"
    assert "DB_PASSWORD=[REDACTED]" in evidence
    assert "SuperSecretPass123!" not in evidence


@pytest.mark.asyncio
async def test_genuine_exposed_sql_dump():
    """Test 6: Genuine exposed backup.sql returns VALID finding."""
    path_info = {"path": "/backup.sql", "severity": "critical", "title": "Exposed SQL dump"}
    sql_content = """-- MySQL dump 10.13  Distrib 8.0.22, for Linux (x86_64)
    -- Host: localhost    Database: app_db
    DROP TABLE IF EXISTS `users`;
    CREATE TABLE `users` (
        `id` int NOT NULL AUTO_INCREMENT,
        `username` varchar(255) NOT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    INSERT INTO `users` VALUES (1,'admin');
    """

    req = httpx.Request("GET", "http://testsite.com/backup.sql")
    res = httpx.Response(200, text=sql_content, request=req, headers={"content-type": "application/x-sql"})

    baseline = {"status_code": 404, "final_url_path": "/sentinelscan-nonexistent", "is_html": False}

    assert _is_soft_404_or_redirect(res, baseline, path_info) is False
    is_valid, evidence, confidence = _validate_content(path_info, res)

    assert is_valid is True
    assert confidence == "high"
    assert "SQL database dump" in evidence


@pytest.mark.asyncio
async def test_genuine_exposed_wordpress_config():
    """Test 7: Genuine exposed wp-config.php.bak returns VALID finding."""
    path_info = {"path": "/wp-config.php.bak", "severity": "critical", "title": "Exposed WordPress config backup"}
    wp_config_content = """<?php
    define( 'DB_NAME', 'wordpress_db' );
    define( 'DB_USER', 'wp_user' );
    define( 'DB_PASSWORD', 'WpSecretPassword99!' );
    define( 'DB_HOST', 'localhost' );
    $table_prefix = 'wp_';
    """

    req = httpx.Request("GET", "http://testsite.com/wp-config.php.bak")
    res = httpx.Response(200, text=wp_config_content, request=req, headers={"content-type": "text/plain"})

    baseline = {"status_code": 404, "final_url_path": "/sentinelscan-nonexistent", "is_html": False}

    assert _is_soft_404_or_redirect(res, baseline, path_info) is False
    is_valid, evidence, confidence = _validate_content(path_info, res)

    assert is_valid is True
    assert confidence == "high"
    assert "WordPress configuration backup" in evidence


def test_secret_redaction_utility():
    """Test secret redaction regex helper."""
    raw = "DB_PASSWORD=SecretPassword123\nAWS_SECRET_ACCESS_KEY=abc123XYZ\nAPP_NAME=MyApp"
    redacted = _redact_secrets(raw)
    assert "DB_PASSWORD=[REDACTED]" in redacted
    assert "AWS_SECRET_ACCESS_KEY=[REDACTED]" in redacted
    assert "APP_NAME=MyApp" in redacted
