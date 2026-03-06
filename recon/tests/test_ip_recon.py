"""
Tests for IP-based targeting features:
- reverse_dns_lookup (domain_recon.py)
- is_host_in_scope IP bypass (http_probe.py)
- build_targets_from_dns IP mode (http_probe.py)
- GAU disable in IP mode (resource_enum.py)
- CIDR expansion logic (main.py)
"""
import ipaddress
import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# CIDR expansion (extracted from main.py run_ip_recon logic)
# ============================================================

def expand_cidrs(target_ips: list) -> list:
    """Reproduce the CIDR expansion logic from run_ip_recon."""
    expanded = []
    for entry in target_ips:
        entry = entry.strip()
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                for host in network.hosts():
                    expanded.append(str(host))
                if network.prefixlen in (32, 128):
                    expanded.append(str(network.network_address))
            except ValueError:
                pass
        else:
            expanded.append(entry)
    return list(dict.fromkeys(expanded))


class TestCidrExpansion:
    def test_single_ip_passthrough(self):
        result = expand_cidrs(['192.168.1.1'])
        assert result == ['192.168.1.1']

    def test_cidr_24_expands_to_254(self):
        result = expand_cidrs(['10.0.0.0/24'])
        assert len(result) == 254
        assert '10.0.0.1' in result
        assert '10.0.0.254' in result
        # Network (10.0.0.0) and broadcast (10.0.0.255) excluded by hosts()
        assert '10.0.0.0' not in result
        assert '10.0.0.255' not in result

    def test_cidr_32_single_host(self):
        result = expand_cidrs(['10.0.0.5/32'])
        assert result == ['10.0.0.5']

    def test_cidr_30_expands_to_2(self):
        result = expand_cidrs(['10.0.0.0/30'])
        assert len(result) == 2
        assert '10.0.0.1' in result
        assert '10.0.0.2' in result

    def test_ipv6_128_single_host(self):
        result = expand_cidrs(['2001:db8::1/128'])
        assert result == ['2001:db8::1']

    def test_mixed_ips_and_cidrs(self):
        result = expand_cidrs(['8.8.8.8', '10.0.0.0/30'])
        assert '8.8.8.8' in result
        assert '10.0.0.1' in result
        assert '10.0.0.2' in result

    def test_deduplication(self):
        result = expand_cidrs(['10.0.0.1', '10.0.0.0/30'])
        assert result.count('10.0.0.1') == 1

    def test_invalid_cidr_skipped(self):
        result = expand_cidrs(['not-a-cidr/24'])
        assert result == []

    def test_whitespace_trimmed(self):
        result = expand_cidrs(['  192.168.1.1  '])
        assert result == ['192.168.1.1']


# ============================================================
# reverse_dns_lookup
# ============================================================

class TestReverseDnsLookup:
    @patch('dns.resolver.resolve')
    @patch('dns.reversename.from_address')
    def test_successful_ptr(self, mock_from_addr, mock_resolve):
        from recon.domain_recon import reverse_dns_lookup

        mock_from_addr.return_value = '1.1.168.192.in-addr.arpa.'
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: 'host.example.com.'
        mock_resolve.return_value = [mock_answer]

        result = reverse_dns_lookup('192.168.1.1')
        assert result == 'host.example.com'

    @patch('dns.resolver.resolve')
    @patch('dns.reversename.from_address')
    def test_nxdomain_returns_none(self, mock_from_addr, mock_resolve):
        import dns.resolver
        from recon.domain_recon import reverse_dns_lookup

        mock_from_addr.return_value = 'test'
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = reverse_dns_lookup('10.0.0.1')
        assert result is None

    @patch('dns.resolver.resolve')
    @patch('dns.reversename.from_address')
    def test_no_answer_returns_none(self, mock_from_addr, mock_resolve):
        import dns.resolver
        from recon.domain_recon import reverse_dns_lookup

        mock_from_addr.return_value = 'test'
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        result = reverse_dns_lookup('10.0.0.1')
        assert result is None

    @patch('dns.resolver.resolve')
    @patch('dns.reversename.from_address')
    def test_timeout_retries(self, mock_from_addr, mock_resolve):
        import dns.resolver
        from recon.domain_recon import reverse_dns_lookup

        mock_from_addr.return_value = 'test'
        mock_resolve.side_effect = dns.resolver.LifetimeTimeout()

        result = reverse_dns_lookup('10.0.0.1', max_retries=2)
        assert result is None
        assert mock_resolve.call_count == 2

    @patch('dns.resolver.resolve')
    @patch('dns.reversename.from_address')
    def test_generic_exception_returns_none(self, mock_from_addr, mock_resolve):
        from recon.domain_recon import reverse_dns_lookup

        mock_from_addr.return_value = 'test'
        mock_resolve.side_effect = Exception("network error")

        result = reverse_dns_lookup('10.0.0.1')
        assert result is None


# ============================================================
# is_host_in_scope with IP bypass
# ============================================================

class TestIsHostInScopeIpBypass:
    def _import(self):
        from recon.http_probe import is_host_in_scope
        return is_host_in_scope

    def test_ip_in_allowed_list(self):
        fn = self._import()
        assert fn('192.168.1.1', 'example.com', allowed_hosts=['192.168.1.1', '10.0.0.1']) is True

    def test_ip_not_in_allowed_list(self):
        fn = self._import()
        assert fn('192.168.1.99', 'example.com', allowed_hosts=['192.168.1.1']) is False

    def test_ip_no_allowed_list_returns_true(self):
        fn = self._import()
        assert fn('192.168.1.1', 'example.com') is True

    def test_ip_empty_allowed_list_returns_true(self):
        fn = self._import()
        assert fn('10.0.0.1', 'example.com', allowed_hosts=[]) is True

    def test_regular_domain_still_works(self):
        fn = self._import()
        assert fn('sub.example.com', 'example.com') is True
        assert fn('evil.com', 'example.com') is False

    def test_ipv6_bypass(self):
        fn = self._import()
        assert fn('2001:db8::1', 'example.com') is True

    def test_ipv6_in_allowed(self):
        fn = self._import()
        assert fn('2001:db8::1', 'example.com', allowed_hosts=['2001:db8::1']) is True

    def test_empty_host_returns_false(self):
        fn = self._import()
        assert fn('', 'example.com') is False

    def test_empty_root_returns_false(self):
        fn = self._import()
        assert fn('192.168.1.1', '') is False


# ============================================================
# build_targets_from_dns with IP mode
# ============================================================

class TestBuildTargetsFromDnsIpMode:
    def _import(self):
        from recon.http_probe import build_targets_from_dns
        return build_targets_from_dns

    def test_ip_mode_uses_actual_ip(self):
        fn = self._import()
        recon_data = {
            "metadata": {"ip_mode": True},
            "dns": {
                "domain": {},
                "subdomains": {
                    "192-168-1-1": {
                        "has_records": True,
                        "is_mock": True,
                        "actual_ip": "192.168.1.1",
                        "ips": {"ipv4": ["192.168.1.1"], "ipv6": []},
                    }
                }
            }
        }
        targets = fn(recon_data)
        # Should contain the actual IP, not the mock name
        assert any('192.168.1.1' in t for t in targets)
        assert not any('192-168-1-1' in t for t in targets)

    def test_ip_mode_real_hostname_used_directly(self):
        fn = self._import()
        recon_data = {
            "metadata": {"ip_mode": True},
            "dns": {
                "domain": {},
                "subdomains": {
                    "server.example.com": {
                        "has_records": True,
                        "is_mock": False,
                        "ips": {"ipv4": ["1.2.3.4"], "ipv6": []},
                    }
                }
            }
        }
        targets = fn(recon_data)
        assert any('server.example.com' in t for t in targets)

    def test_ip_mode_fallback_to_ips(self):
        fn = self._import()
        recon_data = {
            "metadata": {"ip_mode": True},
            "dns": {
                "domain": {},
                "subdomains": {
                    "10-0-0-1": {
                        "has_records": True,
                        "is_mock": True,
                        "actual_ip": "",
                        "ips": {"ipv4": ["10.0.0.1"], "ipv6": []},
                    }
                }
            }
        }
        targets = fn(recon_data)
        assert any('10.0.0.1' in t for t in targets)

    def test_non_ip_mode_uses_subdomain_name(self):
        fn = self._import()
        recon_data = {
            "metadata": {"ip_mode": False},
            "dns": {
                "domain": {},
                "subdomains": {
                    "sub.example.com": {
                        "has_records": True,
                        "ips": {"ipv4": ["1.2.3.4"], "ipv6": []},
                    }
                }
            }
        }
        targets = fn(recon_data)
        assert any('sub.example.com' in t for t in targets)


# ============================================================
# GAU disable in IP mode
# ============================================================

class TestGauIpModeDisable:
    def test_gau_disabled_when_ip_mode(self):
        """Verify the GAU flag logic from resource_enum."""
        metadata = {"ip_mode": True}
        ip_mode = metadata.get("ip_mode", False)
        settings = {'GAU_ENABLED': True}
        result = False if ip_mode else settings.get('GAU_ENABLED', False)
        assert result is False

    def test_gau_enabled_when_domain_mode(self):
        metadata = {"ip_mode": False}
        ip_mode = metadata.get("ip_mode", False)
        settings = {'GAU_ENABLED': True}
        result = False if ip_mode else settings.get('GAU_ENABLED', False)
        assert result is True

    def test_gau_disabled_when_setting_false(self):
        metadata = {"ip_mode": False}
        ip_mode = metadata.get("ip_mode", False)
        settings = {'GAU_ENABLED': False}
        result = False if ip_mode else settings.get('GAU_ENABLED', False)
        assert result is False


# ============================================================
# project_settings defaults
# ============================================================

class TestProjectSettingsDefaults:
    def test_defaults_include_ip_mode(self):
        from recon.project_settings import DEFAULT_SETTINGS
        assert 'IP_MODE' in DEFAULT_SETTINGS
        assert DEFAULT_SETTINGS['IP_MODE'] is False

    def test_defaults_include_target_ips(self):
        from recon.project_settings import DEFAULT_SETTINGS
        assert 'TARGET_IPS' in DEFAULT_SETTINGS
        assert DEFAULT_SETTINGS['TARGET_IPS'] == []
