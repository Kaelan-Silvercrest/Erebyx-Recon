import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.resolver
import requests

from erebyx.core.cli import run as cli_run
from erebyx.i18n import set_language
from erebyx.modules.generic.domain_lookup import (
    DomainLookupModule,
    _analyze_email_security,
    _fetch_ct_subdomains,
    _rdap_dates,
    _registrar_name,
)
from erebyx.modules.generic.email_check import EmailCheckModule
from erebyx.modules.generic.public_contact_lookup import (
    PublicContactLookupModule,
    _parse_security_txt,
    _public_role_addresses,
)
from erebyx.modules.generic.username_check import UsernameCheckModule
from erebyx.modules.indonesia.domain_id_lookup import (
    DomainIdLookupModule,
    _classify_id_zone,
)
from erebyx.utils import output
from erebyx.utils.dns_lookup import (
    DEFAULT_NAMESERVERS,
    DnsResult,
    get_resolver,
    reset_resolver,
)


class ModuleValidationTests(unittest.TestCase):
    def setUp(self):
        set_language("en")

    def test_domain_validation(self):
        module = DomainLookupModule()
        self.assertTrue(module.validate_target("example.co.uk"))
        self.assertFalse(module.validate_target("-bad.example"))
        self.assertFalse(module.validate_target("example..com"))
        self.assertFalse(module.validate_target("example.com/path"))

    def test_email_validation(self):
        module = EmailCheckModule()
        self.assertTrue(module.validate_target("contact@example.com"))
        self.assertFalse(module.validate_target("name..part@example.com"))
        self.assertFalse(module.validate_target("name@example"))
        self.assertFalse(module.validate_target("two@@example.com"))
        self.assertFalse(module.validate_target("name@-example.com"))

    @patch("erebyx.modules.generic.email_check.resolve_records")
    def test_email_null_mx_is_not_reported_as_mail_capable(self, resolve):
        resolve.return_value = (["0 ."], None)
        result = EmailCheckModule().run("contact@example.com")
        self.assertFalse(result.data["domain_has_mail_route"])
        self.assertIn("null MX", result.data["warning"])
        resolve.assert_called_once_with("example.com", "MX")

    @patch("erebyx.modules.generic.email_check.resolve_records")
    def test_email_spf_and_dmarc_evaluation(self, resolve):
        def side_effect(host, rtype):
            if (host, rtype) == ("example.com", "MX"):
                return (["10 mail.example.com."], None)
            if (host, rtype) == ("example.com", "TXT"):
                return (['"v=spf1 include:_spf.example.com -all"'], None)
            if (host, rtype) == ("_dmarc.example.com", "TXT"):
                return (['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'], None)
            return ([], None)

        resolve.side_effect = side_effect
        result = EmailCheckModule().run("security+alert@example.com")
        self.assertTrue(result.success)
        self.assertTrue(result.data["is_role_account"])
        self.assertEqual(result.data["plus_tag"], "alert")
        self.assertEqual(
            result.data["spoofing_protection"], "strong (SPF + enforced DMARC)"
        )
        self.assertEqual(result.data["dns_status"], "OK")
        self.assertNotIn("reason", result.data)

    @patch("erebyx.modules.generic.email_check.resolve_records")
    def test_email_dns_failure_sets_not_checked_and_failed_status(self, resolve):
        resolve.return_value = DnsResult(
            [], "cannot open /etc/resolv.conf", "RESOLVER_UNAVAILABLE"
        )
        result = EmailCheckModule().run("user@gmail.com")
        self.assertTrue(result.success)
        self.assertEqual(result.data["dns_status"], "FAILED")
        self.assertEqual(result.data["reason"], "RESOLVER_UNAVAILABLE")
        self.assertEqual(result.data["mx_records"], "NOT_CHECKED")
        self.assertEqual(result.data["fallback_address_records"], "NOT_CHECKED")
        self.assertEqual(result.data["spf_records"], "NOT_CHECKED")
        self.assertEqual(result.data["dmarc_records"], "NOT_CHECKED")
        self.assertEqual(result.data["spoofing_protection"], "NOT_CHECKED")
        self.assertIsNone(result.data["domain_has_mail_route"])
        self.assertIn("cannot open /etc/resolv.conf", result.data["warning"])

    def test_resolver_fallback_on_missing_resolv_conf(self):
        reset_resolver()
        try:
            with patch(
                "dns.resolver.Resolver",
                side_effect=[
                    dns.resolver.NoResolverConfiguration("cannot open /etc/resolv.conf"),
                    dns.resolver.Resolver(configure=False),
                ],
            ):
                r = get_resolver(force_refresh=True)
                self.assertEqual(r.nameservers, DEFAULT_NAMESERVERS)
        finally:
            reset_resolver()

    def test_resolver_custom_env_servers(self):
        reset_resolver()
        os.environ["EREBYX_DNS_SERVERS"] = "1.0.0.1, 9.9.9.9"
        try:
            r = get_resolver(force_refresh=True)
            self.assertEqual(r.nameservers, ["1.0.0.1", "9.9.9.9"])
        finally:
            del os.environ["EREBYX_DNS_SERVERS"]
            reset_resolver()

    def test_username_module_is_local_only(self):
        module = UsernameCheckModule()
        result = module.run("my_org")
        self.assertTrue(result.success)
        self.assertFalse(result.data["account_search_performed"])
        self.assertEqual(result.data["naming_style"], "snake_case")
        self.assertIn("shannon_entropy_bits", result.data)
        self.assertTrue(module.validate_target("my_org"))
        self.assertFalse(module.validate_target("my org"))

    def test_contact_lookup_only_returns_role_addresses(self):
        page = (
            '<a href="mailto:contact@example.com">Contact</a>'
            "jane.doe@example.com"
            "info@other.example"
            "support@sub.example.com"
        )
        self.assertEqual(
            _public_role_addresses(page, "example.com"),
            {"contact@example.com"},
        )

    def test_security_txt_parser(self):
        raw = (
            "# Official security policy\n"
            "Contact: mailto:security@example.com\n"
            "Policy: https://example.com/security-policy\n"
            "Ignored-Field: something\n"
        )
        parsed = _parse_security_txt(raw)
        self.assertEqual(parsed["contact"], ["mailto:security@example.com"])
        self.assertEqual(parsed["policy"], ["https://example.com/security-policy"])
        self.assertNotIn("ignored-field", parsed)

    def test_contact_lookup_rejects_bad_domain(self):
        module = PublicContactLookupModule()
        self.assertTrue(module.validate_target("example.com"))
        self.assertFalse(module.validate_target("localhost"))
        self.assertFalse(module.validate_target("example.com/path"))

    @patch("erebyx.modules.generic.public_contact_lookup.HttpClient")
    @patch("erebyx.modules.generic.public_contact_lookup.socket.getaddrinfo")
    def test_contact_lookup_rejects_private_network_targets(self, getaddrinfo, client):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        result = PublicContactLookupModule().run("example.com")
        self.assertFalse(result.success)
        client.assert_not_called()

    @patch("erebyx.modules.generic.public_contact_lookup.HttpClient")
    @patch("erebyx.modules.generic.public_contact_lookup.socket.getaddrinfo")
    def test_contact_lookup_ignores_404_on_optional_paths(self, getaddrinfo, client_cls):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ]
        client = MagicMock()
        client_cls.return_value = client

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.__enter__.return_value = resp
            resp.__exit__.return_value = False
            if url == "https://example.com/":
                resp.status_code = 200
                resp.headers = {"Content-Type": "text/html", "Server": "cloudflare"}
                resp.encoding = "utf-8"
                resp.iter_content.return_value = [b"<html>security@example.com</html>"]
            else:
                resp.status_code = 404
                resp.headers = {"Content-Type": "text/html"}
                resp.iter_content.return_value = []
            return resp

        client.get.side_effect = fake_get
        result = PublicContactLookupModule().run("example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.data["warnings"], [])
        self.assertEqual(result.data["public_role_addresses"], ["security@example.com"])
        self.assertEqual(result.data["pages_found"], ["https://example.com/"])

    def test_ct_subdomains_falls_back_to_certspotter(self):
        client = MagicMock()
        spotter_resp = MagicMock()
        spotter_resp.raise_for_status.return_value = None
        spotter_resp.json.return_value = [
            {"dns_names": ["api.example.com", "*.dev.example.com", "other.org"]}
        ]

        def side_effect(url, **kwargs):
            if "crt.sh" in url:
                raise requests.Timeout("crt.sh timed out")
            return spotter_resp

        client.get.side_effect = side_effect
        subs, used_url, warning = _fetch_ct_subdomains(client, "example.com")
        self.assertIsNone(warning)
        self.assertIn("certspotter.com", used_url)
        self.assertEqual(subs, ["api.example.com", "dev.example.com"])

    def test_rdap_fields_are_extracted(self):
        events = [
            {"eventAction": "registration", "eventDate": "2020-01-01"},
            {"eventAction": "expiration", "eventDate": "2030-01-01"},
        ]
        entities = [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrar"]],
                ],
            }
        ]
        self.assertEqual(
            _rdap_dates(events),
            {"created": "2020-01-01", "expires": "2030-01-01"},
        )
        self.assertEqual(_registrar_name(entities), "Example Registrar")

    def test_email_security_helper_parses_spf_dmarc_caa(self):
        sec = _analyze_email_security(
            txt_records=['"v=spf1 -all"'],
            dmarc_records=['"v=DMARC1; p=quarantine;"'],
            caa_records=['0 issue "letsencrypt.org"'],
        )
        self.assertEqual(sec["spf_policy"], "strict (-all)")
        self.assertEqual(sec["dmarc_policy"], "quarantine")
        self.assertTrue(sec["has_caa"])

    def test_domain_id_zone_classification(self):
        module = DomainIdLookupModule()
        self.assertTrue(module.validate_target("contoh.co.id"))
        self.assertFalse(module.validate_target("example.com"))
        zone_id = _classify_id_zone("contoh.go.id", lang="id")
        self.assertEqual(zone_id["ekstensi"], ".go.id")
        self.assertIn("Pemerintah", zone_id["kategori"])
        zone_en = _classify_id_zone("contoh.go.id", lang="en")
        self.assertIn("Government", zone_en["kategori"])

    def test_export_filename_cannot_escape_output_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(output, "OUTPUT_DIR", Path(temp_dir) / "output"):
                saved = output.save_json(
                    {"ok": True},
                    "../../unsafe@example.com",
                    "../module",
                )
                self.assertEqual(saved.parent, Path(temp_dir) / "output")
                self.assertTrue(saved.exists())

    def test_json_export_keeps_stdout_valid_json(self):
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("erebyx.core.cli.save_json", return_value=Path("output/result.json")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = cli_run(
                [
                    "--module",
                    "username_check",
                    "--target",
                    "my_org",
                    "--output",
                    "json",
                    "--export",
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertFalse(json.loads(stdout.getvalue())["data"]["account_search_performed"])
        self.assertIn("output/result.json", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
