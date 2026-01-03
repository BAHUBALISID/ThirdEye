# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to security@example.com.

Do not disclose security vulnerabilities publicly until they have been addressed.

## Security Features

ThirdEye includes the following security features:

### Passive Intelligence Only
- No active scanning or exploitation
- No credential validation
- No authentication attempts
- Read-only operations

### Data Protection
- Sensitive data masking in output
- No persistent storage of credentials
- Encrypted cache (if configured)
- Configurable data retention

### Network Safety
- Rate limiting on API calls
- Timeouts on network operations
- TLS-only external connections
- User-agent identification

### Ethical Enforcement
- Usage disclaimer on first run
- Clear documentation of limitations
- Exit codes for automation safety
- No hidden or malicious functionality

## Responsible Disclosure

We follow responsible disclosure practices:
1. Report vulnerability privately
2. We acknowledge within 48 hours
3. We investigate and create fix
4. We release patch and credit reporter
5. Public disclosure after patch

## Third-Party Dependencies

All dependencies are regularly audited:
- `cargo audit` integration
- Regular dependency updates
- Minimal dependency footprint
- No known vulnerabilities in release

## Usage Guidelines

ThirdEye should only be used:
- On systems you own or have permission to test
- In accordance with applicable laws
- For authorized security assessments
- With respect for privacy and ethics
