import pytest
from datetime import date, timedelta
from unittest.mock import patch
from app.scanner.lifecycle import get_lifecycle_status, build_lifecycle_finding, _version_matches_prefix


class TestVersionMatchesPrefix:
    def test_exact(self): assert _version_matches_prefix('8.2.26', '8.2') is True
    def test_subversion(self): assert _version_matches_prefix('8.2.26-debian', '8.2') is True
    def test_major_only(self): assert _version_matches_prefix('5.6.40', '5') is True
    def test_no_match(self): assert _version_matches_prefix('8.3.10', '8.2') is False
    def test_empty(self): assert _version_matches_prefix('', '8.2') is False


class TestFailClosed:
    def test_none_version(self): assert get_lifecycle_status('PHP', None) is None
    def test_empty_version(self): assert get_lifecycle_status('PHP', '') is None
    def test_unknown_tech(self): assert get_lifecycle_status('UnknownFramework', '1.0.0') is None
    def test_no_prefix_match(self): assert get_lifecycle_status('PHP', '3.0.0') is None


class TestPHP:
    def test_8_4_active(self):
        r = get_lifecycle_status('PHP', '8.4.0')
        assert r['status'] == 'active' and r['eol_date'] == '2028-11-30'
    def test_8_1_security_only(self):
        assert get_lifecycle_status('PHP', '8.1.31')['status'] == 'security-only'
    def test_8_0_eol(self):
        r = get_lifecycle_status('PHP', '8.0.30')
        assert r['status'] == 'eol' and r['eol_date'] == '2023-11-26'
    def test_5_x_eol(self):
        assert get_lifecycle_status('PHP', '5.6.40')['status'] == 'eol'


class TestWordPress:
    def test_7_1_active(self):
        r = get_lifecycle_status('WordPress', '7.1')
        assert r['status'] == 'active' and r['eol_date'] is None
    def test_7_0_security_only(self):
        r = get_lifecycle_status('WordPress', '7.0.4')
        assert r['status'] == 'security-only' and r['eol_date'] is None
    def test_6_6_is_security_only_not_active(self):
        r = get_lifecycle_status('WordPress', '6.6.7')
        assert r['status'] == 'security-only' and r['eol_date'] is None
    def test_6_4_security_only(self):
        r = get_lifecycle_status('WordPress', '6.4.10')
        assert r['status'] == 'security-only' and r['eol_date'] is None
    def test_5_x_eol(self):
        r = get_lifecycle_status('WordPress', '5.9.0')
        assert r['status'] == 'eol' and r['eol_date'] is None
    def test_4_x_eol(self):
        r = get_lifecycle_status('WordPress', '4.9.23')
        assert r['status'] == 'eol' and r['eol_date'] is None
    def test_3_x_no_entry(self):
        assert get_lifecycle_status('WordPress', '3.9.0') is None


class TestApache:
    def test_2_4_active_no_eol_date(self):
        r = get_lifecycle_status('Apache', '2.4.62')
        assert r['status'] == 'active' and r['eol_date'] is None
    def test_2_2_eol(self):
        r = get_lifecycle_status('Apache', '2.2.34')
        assert r['status'] == 'eol' and r['eol_date'] == '2017-12-31'
    def test_2_0_eol(self):
        assert get_lifecycle_status('Apache', '2.0.65')['status'] == 'eol'


class TestIIS:
    def test_10_active(self):
        r = get_lifecycle_status('IIS', '10.0')
        assert r['status'] == 'active' and r['eol_date'] == '2031-10-14'
    def test_8_5_eol(self):
        r = get_lifecycle_status('IIS', '8.5.9600')
        assert r['status'] == 'eol' and r['eol_date'] == '2023-10-10'


class TestNginx:
    def test_1_26_active(self):
        assert get_lifecycle_status('Nginx', '1.26.3')['status'] == 'active'
    def test_1_24_eol(self):
        assert get_lifecycle_status('Nginx', '1.24.0')['status'] == 'eol'


class TestNoneDateRendering:
    def test_eol_none_no_none_string(self):
        lc = {'status': 'eol', 'eol_date': None, 'note': 'n', 'source': 'https://wordpress.org/'}
        f = build_lifecycle_finding('WordPress', '5.9.0', lc)
        assert f is not None and 'None' not in f['description'] and 'None' not in f['title']
    def test_security_only_none_no_none_string(self):
        lc = {'status': 'security-only', 'eol_date': None, 'note': 'n', 'source': 'https://wordpress.org/'}
        f = build_lifecycle_finding('WordPress', '6.6.7', lc)
        assert f is not None and 'None' not in f['description'] and 'None' not in f['recommendation']
    def test_active_no_finding(self):
        lc = {'status': 'active', 'eol_date': None, 'note': 'n', 'source': 'https://example.com'}
        assert build_lifecycle_finding('WordPress', '7.1', lc) is None


class TestEOLNotCVE:
    def test_eol_not_confirmed_cve(self):
        lc = {'status': 'eol', 'eol_date': '2023-11-26', 'note': 'EOL', 'source': 'https://www.php.net/eol.php'}
        f = build_lifecycle_finding('PHP', '8.0.30', lc)
        assert f is not None
        assert 'is therefore vulnerable' not in f['description']
        assert 'CVE correlation' in f['description']
    def test_eol_references_source(self):
        lc = {'status': 'eol', 'eol_date': '2023-11-26', 'note': 'EOL', 'source': 'https://www.php.net/eol.php'}
        f = build_lifecycle_finding('PHP', '8.0.30', lc)
        assert 'https://www.php.net/eol.php' in f['references']
    def test_security_only_low(self):
        lc = {'status': 'security-only', 'eol_date': '2025-12-31', 'note': 'n', 'source': 'https://php.net/'}
        assert build_lifecycle_finding('PHP', '8.1.31', lc)['severity'] == 'low'
    def test_eol_high(self):
        lc = {'status': 'eol', 'eol_date': '2023-11-26', 'note': 'n', 'source': 'https://php.net/'}
        assert build_lifecycle_finding('PHP', '8.0.30', lc)['severity'] == 'high'


class TestApproachingEOL:
    def test_triggers_within_180_days(self):
        from datetime import date, timedelta
        future = (date.today() + timedelta(days=90)).isoformat()
        with patch('app.scanner.lifecycle._LIFECYCLE_DB', {
            'T': [{'version_prefix': '1.0', 'eol_date': future, 'status': 'active', 'note': 't', 'source': 'https://e.com'}]
        }):
            assert get_lifecycle_status('T', '1.0.5')['status'] == 'approaching-eol'
    def test_no_trigger_far_future(self):
        from datetime import date, timedelta
        far = (date.today() + timedelta(days=400)).isoformat()
        with patch('app.scanner.lifecycle._LIFECYCLE_DB', {
            'T': [{'version_prefix': '2.0', 'eol_date': far, 'status': 'active', 'note': 't', 'source': 'https://e.com'}]
        }):
            assert get_lifecycle_status('T', '2.0.0')['status'] == 'active'
    def test_none_eol_date_no_approaching_eol(self):
        r = get_lifecycle_status('WordPress', '7.1')
        assert r is not None and r['status'] == 'active'
