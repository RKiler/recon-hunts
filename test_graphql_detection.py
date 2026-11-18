import unittest

from js_analysis import classify_graphql_response, is_graphql_candidate_url


class GraphqlDetectionTests(unittest.TestCase):
    def test_candidate_url_detection(self) -> None:
        self.assertTrue(is_graphql_candidate_url("https://example.com/api/graphql"))
        self.assertTrue(is_graphql_candidate_url("https://example.com/api?operationName=Viewer"))
        self.assertFalse(is_graphql_candidate_url("https://example.com/api/users"))

    def test_confirms_typename_response(self) -> None:
        result = classify_graphql_response(
            200,
            "application/json",
            '{"data":{"__typename":"Query"}}',
        )
        self.assertEqual("confirmed", result["confidence"])

    def test_recognizes_graphql_errors(self) -> None:
        result = classify_graphql_response(
            400,
            "application/graphql-response+json",
            '{"errors":[{"message":"Cannot query field nope on type Query"}]}',
        )
        self.assertEqual("probable", result["confidence"])

    def test_rejects_generic_html(self) -> None:
        result = classify_graphql_response(
            200,
            "text/html; charset=utf-8",
            "<html><body>Application</body></html>",
        )
        self.assertEqual("rejected", result["confidence"])


if __name__ == "__main__":
    unittest.main()
