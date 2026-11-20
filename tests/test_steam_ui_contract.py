from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _between(source, start, end):
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


class SteamGuardTemplateContractTests(unittest.TestCase):
    def test_guard_type_is_preserved_in_turkish_and_english_flows(self):
        for relative_path in ("templates/index.html", "templates/en/index.html"):
            with self.subTest(template=relative_path):
                source = PROJECT_ROOT.joinpath(relative_path).read_text(
                    encoding="utf-8"
                )
                add_flow = _between(
                    source,
                    "function doAcctLogin()",
                    "function setAcctMsg(",
                )
                reconnect_render = _between(
                    source,
                    "function renderReconnect(",
                    "function doReconnectSmart(",
                )
                reconnect_flow = _between(
                    source,
                    "function doReconnectSmart(",
                    "function renderDetail(",
                )

                self.assertIn("acctGuardType=null", source)
                self.assertIn("var ect=acctGuardType||(c?'2fa':'email');", add_flow)
                self.assertIn("code_type:ect", add_flow)
                self.assertIn(
                    "(r.code_type==='email'||r.code_type==='2fa')",
                    add_flow,
                )

                self.assertIn("acctGuardType=null", reconnect_render)
                self.assertIn(
                    "var ect=acctGuardType||(code?'2fa':'email');",
                    reconnect_flow,
                )
                self.assertIn(
                    "var useSavedCredentials=hasCredentials&&!p;",
                    reconnect_flow,
                )
                self.assertEqual(reconnect_flow.count("code_type:ect"), 2)
                self.assertIn(
                    "(r.code_type==='email'||r.code_type==='2fa')",
                    reconnect_flow,
                )

                self.assertNotIn("acctGuardType==='email'?'2fa'", source)
                self.assertNotIn("code_type:code?'2fa':'email'", reconnect_flow)
                self.assertNotIn("code_type:'2fa'", reconnect_flow)

    def test_profile_ui_is_offline_capable_and_ignores_stale_responses(self):
        for relative_path in ("templates/index.html", "templates/en/index.html"):
            with self.subTest(template=relative_path):
                source = PROJECT_ROOT.joinpath(relative_path).read_text(
                    encoding="utf-8"
                )
                select_flow = _between(
                    source,
                    "function selectAcct(id)",
                    "function removeAcct(",
                )
                profile_flow = _between(
                    source,
                    "function loadSteamProfile(acctId)",
                    "function formatUptime(",
                )

                self.assertIn("loadSteamProfile(id);", select_flow)
                self.assertNotIn("if(a.logged_in){loadSteamProfile", select_flow)
                self.assertIn("var requestId=++steamProfileRequest;", profile_flow)
                self.assertIn("activeAcct!==acctId", profile_flow)
                self.assertIn('rel="noopener noreferrer"', profile_flow)
                self.assertIn("escapeHtml(d.steamid)", profile_flow)


if __name__ == "__main__":
    unittest.main()
