# Env Guard 🛡️

Fast, zero-dependency secret scanner and pre-commit hook preventing accidental leaks of OpenAI, AWS, and GitHub tokens.

## Usage
```python
from env_guard import scan_text
findings = scan_text("code...")
```
