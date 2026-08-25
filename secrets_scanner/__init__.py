"""secrets_scanner — a git-aware secrets scanner.

Scans working-tree files and full git history for leaked credentials
(API keys, tokens, passwords, private keys) using regex signatures and
Shannon-entropy analysis, with false-positive reduction, severity scoring,
and optional opt-in live verification.
"""

__version__ = "0.1.0"
