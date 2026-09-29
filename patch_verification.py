from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class PatchVerification:
    patch_id: str
    applied: bool
    tests_passed: bool
    security_checks_passed: bool
    regression_count: int = 0

    @property
    def safe_to_release(self) -> bool:
        return self.applied and self.tests_passed and self.security_checks_passed and self.regression_count == 0
