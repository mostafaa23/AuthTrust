"""Priority ranking, candidate-finding classification, and false-positive
reduction.

Important: this module's role is to *assist the analyst*, not to declare
a vulnerability confirmed on its own. Every finding must keep the raw
evidence from the scanner plus an explanation of why it was ranked the
way it was.
"""


def rank_findings(findings: list) -> list:
    raise NotImplementedError
