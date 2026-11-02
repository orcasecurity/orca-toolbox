from iam_ape.conditions import conjoin, negate

REGION = "aws:RequestedRegion"


def test_values_both_required_and_excluded_are_removed() -> None:
    assert conjoin(
        (("StringEquals", REGION, ("eu-west-1", "us-east-1")),),
        (("StringNotEquals", REGION, ("eu-west-1",)),),
    ) == (("StringEquals", REGION, ("us-east-1",)),)


def test_every_required_value_excluded_is_unsatisfiable() -> None:
    assert (
        conjoin(
            (("StringEquals", REGION, ("eu-west-1",)),),
            (("StringNotEquals", REGION, ("eu-west-1",)),),
        )
        is None
    )


def test_conflicting_null_checks_are_unsatisfiable() -> None:
    assert (
        conjoin(
            (("Null", "aws:SourceVpc", ("true",)),),
            (("Null", "aws:SourceVpc", ("false",)),),
        )
        is None
    )


def test_negating_a_positive_clause_holds_when_the_key_is_absent() -> None:
    assert negate(("NumericLessThan", "aws:MultiFactorAuthAge", ("10",))) == (
        ("NumericGreaterThanEqualsIfExists", "aws:MultiFactorAuthAge", ("10",)),
    )


def test_negation_already_true_when_the_key_is_absent() -> None:
    assert negate(("StringEquals", REGION, ("us-east-1",))) == (
        ("StringNotEquals", REGION, ("us-east-1",)),
    )


def test_operator_without_a_negation() -> None:
    assert negate(("BinaryEquals", "aws:SourceVpc", ("QmluYXJ5",))) is None
