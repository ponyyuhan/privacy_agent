.PHONY: paper test specs

paper:
\tbash scripts/build_paper.sh

specs:
\tpython scripts/validate_specs.py

test:
\tpython -m unittest discover -s tests -p 'test_*.py'

