# Security Policy

## Reporting a Vulnerability

If you discover a security issue in Axess, please report it by emailing security@gnomes.ch or opening a private issue on GitHub.

## Using Axess Securely

Axess is a library for authentication and authorization. Its security depends on correct integration and configuration in your application. We recommend:

- Use HTTPS for all authentication flows in your application.
- Enable multi-factor authentication where possible.
- Regularly update Axess and its dependencies.
- Carefully review and test your authorization policies for least privilege.
- Secure session and credential storage according to your threat model.
- Audit your integration for common web vulnerabilities (e.g., XSS, CSRF).

## Supported Versions

We recommend using the latest release of Axess and actively maintained branches.

## Disclaimer

Axess is provided as a library. While we strive for secure defaults, the overall security of your application depends on your usage and integration.
