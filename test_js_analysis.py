import unittest

from js_analysis import (
    extract_js_signals,
    extract_js_urls_from_text,
    extract_script_urls_from_html,
    extract_source_map_urls_from_js,
)


class JsEndpointExtractionTests(unittest.TestCase):
    def assertEndpoint(self, source: str, expected: str) -> None:
        signals = extract_js_signals(source)
        found = set(signals["api_urls"] + signals["endpoint_paths"])
        self.assertIn(expected, found)

    def test_common_js_endpoint_shapes(self) -> None:
        cases = [
            ('fetch("/api/bot-apps")', "/api/bot-apps"),
            ("axios.post('/api/users/:id/invite')", "/api/users/:id/invite"),
            ("request({ url: '/api/orgs/${orgId}/members?role=admin' })", "/api/orgs/${orgId}/members?role=admin"),
            ("new URL('/graphql', window.location.origin)", "/graphql"),
            ("const route = 'api/v1/users/search'", "/api/v1/users/search"),
            (r'const escaped = "\\u002fapi\\u002fescaped\\x2Froute"', "/api/escaped/route"),
            ('const u = "https://example.com/api/v2/accounts?org_id=123"', "https://example.com/api/v2/accounts?org_id=123"),
            ("const nextData = '/_next/data/build-id/admin/users.json'", "/_next/data/build-id/admin/users.json"),
        ]
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.assertEndpoint(source, expected)

    def test_ignores_static_asset_noise(self) -> None:
        signals = extract_js_signals('const icon="/static/logo.svg"; const css="/assets/app.css";')
        found = set(signals["api_urls"] + signals["endpoint_paths"])
        self.assertNotIn("/static/logo.svg", found)
        self.assertNotIn("/assets/app.css", found)

    def test_extracts_graphql_client_signals(self) -> None:
        source = """
        const client = new ApolloClient({ uri: "/api/graphql" });
        const query = gql`query CurrentViewer { viewer { id } }`;
        const mutation = gql`mutation UpdateName($name: String!) { updateName(name: $name) { id } }`;
        const persisted = { sha256Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
        const subscriptions = "wss://stream.example.com/graphql";
        """
        signals = extract_js_signals(source)
        self.assertIn("/api/graphql", signals["graphql_client_endpoints"])
        self.assertIn(
            {"type": "query", "name": "CurrentViewer"},
            signals["graphql_operations"],
        )
        self.assertIn(
            {"type": "mutation", "name": "UpdateName"},
            signals["graphql_operations"],
        )
        self.assertIn(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            signals["graphql_persisted_query_hashes"],
        )
        self.assertIn(
            "wss://stream.example.com/graphql",
            signals["graphql_websocket_urls"],
        )

    def test_correlates_only_bounded_dom_and_message_flows(self) -> None:
        nearby = extract_js_signals(
            "const q=location.search; panel.innerHTML=q; "
            "addEventListener('message', e => { const value=e.data; fetch(value.url); });"
        )
        self.assertGreater(nearby["dom_source_sink_proximity_count"], 0)
        self.assertGreater(nearby["postmessage_data_flow_count"], 0)
        self.assertGreater(nearby["postmessage_sensitive_effect_count"], 0)

        distant = extract_js_signals(
            "location.hash;" + ("x" * 3000) + "panel.innerHTML='constant';"
        )
        self.assertEqual(0, distant["dom_source_sink_proximity_count"])

    def test_extracts_relative_js_imports_from_parent_directory(self) -> None:
        source = '''
        import{D as DropboxApiService}from"./DropboxApiService-DanZ7mxp.js";
        import "./side-effect-BkETKk3E.js";
        const lazy = () => import("../chunks/lazy-CmjPu89k.mjs");
        '''
        urls = extract_js_urls_from_text(
            "https://careers.tesco.com/portalpacks/web/js/body.D8uTc-St.js",
            source,
        )
        self.assertIn(
            "https://careers.tesco.com/portalpacks/web/js/DropboxApiService-DanZ7mxp.js",
            urls,
        )
        self.assertIn(
            "https://careers.tesco.com/portalpacks/web/js/side-effect-BkETKk3E.js",
            urls,
        )
        self.assertIn(
            "https://careers.tesco.com/portalpacks/web/chunks/lazy-CmjPu89k.mjs",
            urls,
        )
        self.assertNotIn("https://careers.tesco.com/DropboxApiService-DanZ7mxp.js", urls)
        self.assertNotIn("https://careers.tesco.com/chunks/lazy-CmjPu89k.mjs", urls)

    def test_ignores_escaped_regex_js_suffix_noise(self) -> None:
        urls = extract_js_urls_from_text(
            "https://careers.tesco.com/ASSET/wizard/select2.full.min.js",
            r"var matcher = /\\.js$/i; var escaped = '\\.mjs';",
        )
        self.assertEqual([], urls)

    def test_malformed_bracketed_js_url_does_not_hide_valid_urls(self) -> None:
        urls = extract_js_urls_from_text(
            "https://app.example.com/static/app.js",
            'const bad="https://[bad]/broken.js"; const good="https://cdn.example.com/good.js";',
        )
        self.assertEqual(["https://cdn.example.com/good.js"], urls)

        signals = extract_js_signals(
            'const bad="https://[bad]/api/users"; const good="https://api.example.com/api/users";'
        )
        self.assertEqual(["https://api.example.com/api/users"], signals["api_urls"])

    def test_malformed_bracketed_script_and_source_map_urls_are_skipped(self) -> None:
        scripts = extract_script_urls_from_html(
            "https://app.example.com/",
            '<script src="https://[bad]/broken.js"></script><script src="/good.js"></script>',
        )
        maps = extract_source_map_urls_from_js(
            "https://app.example.com/app.js",
            "//# sourceMappingURL=https://[bad]/app.js.map",
        )
        self.assertEqual(["https://app.example.com/good.js"], scripts)
        self.assertEqual(["https://app.example.com/app.js.map"], maps)

    def test_valid_ipv6_js_url_is_preserved(self) -> None:
        urls = extract_js_urls_from_text(
            "https://app.example.com/static/app.js",
            'const chunk="https://[2001:db8::1]/chunk.js";',
        )
        self.assertEqual(["https://[2001:db8::1]/chunk.js"], urls)


if __name__ == "__main__":
    unittest.main()
