import unittest

from hunt_research import (
    extract_research_observations,
    merge_evidence_level,
    merge_research_state,
    reconcile_validation_state,
    research_completion,
)


class HuntResearchNormalizationTests(unittest.TestCase):
    def test_malformed_results_are_ignored(self):
        self.assertEqual(extract_research_observations(None), [])
        self.assertEqual(extract_research_observations({"leads": "not-a-list"}), [])

    def test_equivalent_identity_path_observations_share_a_dedup_key(self):
        killed = {
            "killed": [{
                "title": "Login ID path authorization was enforced",
                "bug_class": "IDOR / broken access control",
                "affected_asset": "https://www.finn.no/api/conversations/loginId/123456",
                "controlled_input": "loginId path identity",
                "expected_boundary": "path identity must bind to session identity",
                "reason": "Other-account control was denied",
            }]
        }
        lead = {
            "leads": [{
                "title": "Login ID path may cross an account boundary",
                "bug_class": "BOLA authorization",
                "affected_asset": "https://www.finn.no/api/conversations/loginId/987654",
                "controlled_input": "loginId path identity",
                "expected_boundary": "path identity must bind to session identity",
                "hypothesis_proof": {"observed_behavior": "Differential response observed"},
            }]
        }
        killed_observation = extract_research_observations(killed)[0]
        lead_observation = extract_research_observations(lead)[0]
        self.assertEqual(killed_observation.dedup_key, lead_observation.dedup_key)
        self.assertEqual(
            merge_research_state(killed_observation.state, lead_observation.state),
            "needs_reconciliation",
        )

    def test_distinct_controlled_objects_do_not_collapse(self):
        common = {
            "title": "Conversation authorization",
            "bug_class": "IDOR",
            "affected_asset": "https://www.finn.no/api/conversations/123456",
            "expected_boundary": "object ownership",
        }
        identity = extract_research_observations({"leads": [{
            **common, "controlled_input": "loginId path identity",
        }]})[0]
        conversation = extract_research_observations({"leads": [{
            **common, "controlled_input": "conversationId object",
        }]})[0]
        self.assertNotEqual(identity.dedup_key, conversation.dedup_key)

    def test_confirmation_is_sticky_and_evidence_never_downgrades(self):
        self.assertEqual(merge_research_state("confirmed", "killed"), "confirmed")
        self.assertEqual(merge_research_state("candidate", "killed"), "needs_reconciliation")
        self.assertEqual(merge_evidence_level("E3", "E0"), "E3")

    def test_supported_requires_baseline_and_negative_control(self):
        base = {
            "title": "Cross-account object read",
            "bug_class": "IDOR",
            "affected_asset": "https://example.test/api/object/123",
        }
        candidate = extract_research_observations({"leads": [base]})[0]
        supported = extract_research_observations({"leads": [{
            **base, "baseline": "owner read", "negative_control": "invalid object denied",
        }]})[0]
        self.assertEqual((candidate.state, candidate.evidence_level), ("candidate", "E1"))
        self.assertEqual((supported.state, supported.evidence_level), ("supported", "E2"))

    def test_inventory_and_research_completion_are_independent(self):
        self.assertEqual(
            research_completion(True, {"needs_reconciliation": 1}),
            {"inventory_state": "inventory_exhausted", "research_state": "reconciliation_required"},
        )
        self.assertEqual(
            research_completion(False, {"candidate": 1}),
            {"inventory_state": "inventory_in_progress", "research_state": "validation_ready"},
        )

    def test_reconciliation_requires_a_controlled_action_result(self):
        controls = {"baseline": "owner success", "negative_control": "invalid object denied"}
        self.assertEqual(
            reconcile_validation_state("needs_reconciliation", "killed", False, controls, "evidence.json"),
            "needs_reconciliation",
        )
        self.assertEqual(
            reconcile_validation_state("needs_reconciliation", "killed", True, {}, "evidence.json"),
            "needs_reconciliation",
        )
        self.assertEqual(
            reconcile_validation_state("needs_reconciliation", "killed", True, controls, "evidence.json"),
            "killed",
        )
        self.assertEqual(
            reconcile_validation_state("needs_reconciliation", "supported", True, controls, "evidence.json"),
            "supported",
        )


if __name__ == "__main__":
    unittest.main()
