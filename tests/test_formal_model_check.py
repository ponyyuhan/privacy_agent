from __future__ import annotations

import unittest

from formal.secureclaw_model_check import check_model


class FormalModelCheckTests(unittest.TestCase):
    def test_model_check_nbe_consistency(self) -> None:
        ok, report = check_model(ttl_s=1, max_issues=2, max_depth=6)
        self.assertTrue(ok, msg=str(report))


if __name__ == "__main__":
    unittest.main()

