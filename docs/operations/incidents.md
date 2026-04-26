# Incident Handling Baseline

## Security Incidents

At minimum, the project must support documented procedures for:
- compromised signing key
- refresh token replay detection
- tenant administrator compromise
- backup disclosure
- broken migration affecting auth availability

## Immediate Response Expectations

- identify affected tenant and scope
- preserve audit evidence
- revoke affected sessions or token families
- rotate impacted credentials or keys
- produce an incident timeline with technical facts only
