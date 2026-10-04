# Version 0.2 risk scoring

The score is the sum of the documented weights in `scoring.py`, capped at 100. A distinct indicator contributes at most once, even when it matches multiple times or appears on multiple URLs. Informational facts such as the TLD, registered domain, HTTPS use, and disabled reputation results do not add risk points. With optional RDAP lookups enabled, a reported registration age of 30 days or less contributes the `domain_age` weight of 15. A Spamhaus DBL listing contributes the `domain_reputation` weight of 20. Missing or unavailable results are unknown and add no points. Both lookups default off. HTTPS is explicitly not proof that a site is legitimate.

The labels are: 0 positive indicators → **Unable to determine**; 1–24 → **Low risk**; 25–49 → **Suspicious**; 50–74 → **High risk**; 75–100 → **Very high risk**. Zero is reserved for thin evidence rather than treated as a safety result.

Confidence reflects agreement among different positively detected, weighted indicators. With no positive indicators it is 0.10. Otherwise it is `min(0.92, 0.20 + 0.12 × (indicator_count − 1))`. This is an evidence-agreement measure, not a calibrated probability of fraud. The threshold and weights are initial, inspectable rules and have not been evaluated against a labeled dataset.
