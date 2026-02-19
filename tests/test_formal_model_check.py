from __future__ import annotations

import unittest

from formal.secureclaw_model_check import check_all_models


class FormalModelCheckTests(unittest.TestCase):
    def test_model_check_nbe_consistency(self) -> None:
        ok, report = check_all_models()
        self.assertTrue(ok, msg=str(report))


if __name__ == "__main__":
    unittest.main()
