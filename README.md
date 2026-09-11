# Enterprise Outbound Security

Enterprise architecture working notes and draft standards for securing outbound network traffic from enterprise users, servers, applications, containers and cloud workloads to Internet-hosted services.

## Current draft

- [Enterprise Outbound Network Security – Requirements, Patterns and Trade-offs](docs/enterprise-outbound-security.md)
- [Change Log / Additions](CHANGELOG.md)

## Status

This repository is a working draft. The intent is to evolve the material into an enterprise security standard and reference architecture.

## Core design position

There should not be a single outbound pattern for every workload. Use a risk-tiered model:

1. Prefer private connectivity/private service endpoints where practical for sensitive or strategic services.
2. Use authenticated Layer-7 proxy / Secure Web Gateway controls where identity, URL/content inspection, DLP or strong web policy is required and the application/protocol is compatible.
3. Use protective DNS plus stateful Layer-3/4 firewall controls for workloads that need Internet access but do not require or cannot tolerate full proxying.
4. Permit controlled direct Internet egress only as an explicit exception, with destination restrictions, enterprise DNS, stable egress identity, telemetry and compensating controls.
5. Prohibit unrestricted direct Internet access from enterprise workloads by default.

## Change management

Material changes should be recorded in `CHANGELOG.md` with the date, scope and rationale. Future topics and design decisions can also be tracked using GitHub issues.
