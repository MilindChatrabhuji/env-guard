from env_guard import scan_text

def test_detect_secrets():
    content = "openai_key = 'sk-1234567890abcdef1234567890abcdef'\nsafe_var = 'hello'"
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].rule_name == "OpenAI API Key"
    assert findings[0].line_number == 1

def test_no_secrets():
    content = "database_url = 'sqlite:///test.db'\nport = 8000"
    assert len(scan_text(content)) == 0
