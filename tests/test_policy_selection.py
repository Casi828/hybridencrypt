"""
test_policy_selection.py — select_encryption_method() scoring behavior.

Covers the RSA/ECC ranking rules directly, including the documented decision
that compliance_level contributes no score to either algorithm and that ties
resolve to ECC. test_policy_classification.py covers determine_classification().

Run with: python3 -m unittest test_policy_selection -v
"""

from __future__ import annotations

import unittest

from spy.policy_engine import PolicyError, select_encryption_method


class TestComplianceIsNeutral(unittest.TestCase):
    """compliance_level must not bias the RSA-versus-ECC choice.

    RSA-3072+ and P-256 ECC are both NIST-approved at ~128-bit equivalent
    strength (SP 800-57 Part 1 Rev. 5), so compliance level gates whether an
    algorithm is acceptable — it does not rank two acceptable options.
    """

    def test_strict_alone_ties_to_ecc(self):
        """Strict compliance with no other signal scores 0-0 and resolves to ECC.

        This is the documented tie-break, not an accident: with the RSA
        compliance bonus removed, rsa_score == ecc_score == 0 and the selector
        returns ECC.
        """
        self.assertEqual(select_encryption_method({"compliance_level": "strict"}), "ecc")

    def test_moderate_alone_ties_to_ecc(self):
        """Moderate compliance likewise carries no RSA bonus."""
        self.assertEqual(select_encryption_method({"compliance_level": "moderate"}), "ecc")

    def test_none_alone_ties_to_ecc(self):
        self.assertEqual(select_encryption_method({"compliance_level": "none"}), "ecc")

    def test_empty_context_ties_to_ecc(self):
        """No signals at all is the same 0-0 tie."""
        self.assertEqual(select_encryption_method({}), "ecc")

    def test_compliance_level_does_not_change_outcome(self):
        """Every compliance level yields the same result for an otherwise fixed context."""
        for env in ("mobile", "enterprise", "embedded", "cloud"):
            for legacy in (False, True):
                results = {
                    select_encryption_method({
                        "environment": env,
                        "compliance_level": level,
                        "legacy_support_required": legacy,
                    })
                    for level in ("strict", "moderate", "none")
                }
                self.assertEqual(
                    len(results), 1,
                    f"compliance_level changed the outcome for env={env!r} legacy={legacy}: {results}",
                )


class TestSignalDrivenSelection(unittest.TestCase):
    """Real deployment signals — not compliance — decide the method."""

    def test_strict_with_legacy_support_selects_rsa(self):
        """Legacy support is the only RSA-favoring signal here, and it wins."""
        self.assertEqual(
            select_encryption_method({
                "compliance_level": "strict",
                "legacy_support_required": True,
            }),
            "rsa",
        )

    def test_strict_with_mobile_selects_ecc(self):
        self.assertEqual(
            select_encryption_method({
                "environment": "mobile",
                "compliance_level": "strict",
            }),
            "ecc",
        )

    def test_strict_with_high_performance_selects_ecc(self):
        self.assertEqual(
            select_encryption_method({
                "compliance_level": "strict",
                "performance_priority": "high",
            }),
            "ecc",
        )

    def test_strict_with_low_bandwidth_selects_ecc(self):
        self.assertEqual(
            select_encryption_method({
                "compliance_level": "strict",
                "bandwidth_constraint": "low",
            }),
            "ecc",
        )

    def test_strict_enterprise_alone_selects_rsa(self):
        """Enterprise environment (+2 RSA) still selects RSA on its own merit."""
        self.assertEqual(
            select_encryption_method({
                "environment": "enterprise",
                "compliance_level": "strict",
            }),
            "rsa",
        )

    def test_legacy_support_can_be_outweighed_by_ecc_signals(self):
        """Legacy (+3 RSA) loses to mobile (+3 ECC) plus low bandwidth (+2 ECC)."""
        self.assertEqual(
            select_encryption_method({
                "environment": "mobile",
                "compliance_level": "strict",
                "legacy_support_required": True,
                "bandwidth_constraint": "low",
            }),
            "ecc",
        )


class TestTieBreak(unittest.TestCase):
    """Ties resolve to ECC by design, at any score — not just 0-0."""

    def test_nonzero_tie_resolves_to_ecc(self):
        """Enterprise (+2 RSA) versus medium performance + medium bandwidth (+2 ECC)."""
        self.assertEqual(
            select_encryption_method({
                "environment": "enterprise",
                "compliance_level": "strict",
                "performance_priority": "medium",
                "bandwidth_constraint": "medium",
            }),
            "ecc",
        )

    def test_high_score_tie_resolves_to_ecc(self):
        """Enterprise + legacy (+5 RSA) versus high performance + low bandwidth (+5 ECC)."""
        self.assertEqual(
            select_encryption_method({
                "environment": "enterprise",
                "compliance_level": "none",
                "legacy_support_required": True,
                "performance_priority": "high",
                "bandwidth_constraint": "low",
            }),
            "ecc",
        )


class TestValidationUnchanged(unittest.TestCase):
    """Removing the compliance bonus must not weaken input validation."""

    def test_invalid_compliance_level_rejected(self):
        with self.assertRaises(PolicyError):
            select_encryption_method({"compliance_level": "ultra"})

    def test_invalid_compliance_level_rejected_alongside_valid_signals(self):
        with self.assertRaises(PolicyError):
            select_encryption_method({
                "environment": "mobile",
                "compliance_level": "fips-140-3",
                "performance_priority": "high",
            })

    def test_invalid_environment_rejected(self):
        with self.assertRaises(PolicyError):
            select_encryption_method({"environment": "mainframe", "compliance_level": "strict"})

    def test_non_dict_context_rejected(self):
        with self.assertRaises(PolicyError):
            select_encryption_method("strict")  # type: ignore[arg-type]


class TestDeterminism(unittest.TestCase):
    """Selection depends only on values, never on dict iteration order."""

    CASES = (
        {"compliance_level": "strict"},
        {"compliance_level": "strict", "legacy_support_required": True},
        {"environment": "enterprise", "compliance_level": "moderate",
         "performance_priority": "medium", "bandwidth_constraint": "medium"},
        {"environment": "mobile", "compliance_level": "none",
         "performance_priority": "high", "legacy_support_required": True,
         "bandwidth_constraint": "low"},
    )

    def test_repeated_calls_are_stable(self):
        for ctx in self.CASES:
            expected = select_encryption_method(ctx)
            for _ in range(10):
                self.assertEqual(select_encryption_method(ctx), expected, f"unstable for {ctx!r}")

    def test_key_insertion_order_does_not_matter(self):
        for ctx in self.CASES:
            expected = select_encryption_method(ctx)
            reordered = dict(reversed(list(ctx.items())))
            self.assertEqual(
                select_encryption_method(reordered), expected,
                f"key order changed the outcome for {ctx!r}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
