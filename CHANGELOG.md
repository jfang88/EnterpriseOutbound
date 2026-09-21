# Change Log

This file tracks material additions and changes to the Enterprise Outbound Security working drafts.

## 2026-09-22 — Draft v0.3

### Added

- Added a dedicated human-operated SFTP outbound-transfer use case in `docs/use-cases/human-sftp-egress.md`.
- Added an SFTP pattern to the main enterprise outbound architecture and Appendix B summary.
- Documented the multi-tenant SFTP risk: an approved hostname/provider does not necessarily identify or restrict the logical recipient/subscriber.
- Compared SFTP exfiltration risk with Microsoft 365 external-tenant exfiltration and highlighted the difference between network destination authorization and logical tenant/recipient authorization.
- Added endpoint control recommendations including Endpoint DLP, application control, EDR detections, managed host keys and controlled staging.
- Added network controls including default-deny outbound TCP/22, provider-specific allowlisting, enterprise DNS, fixed egress IP and transfer-volume analytics.
- Added provider-side controls including source-IP restrictions, named identities, recipient/folder restrictions, virtual-folder isolation, shell/tunnelling restrictions and audit export.
- Added a locked-down transfer VDI/workstation pattern as an interim higher-assurance option.
- Defined enterprise Managed File Transfer / secure transfer as the strategic target for recurring or sensitive human file transfer.
- Added twelve proposed SFTP-specific requirements (`SFTP-01` through `SFTP-12`).
- Added a fifteen-item SFTP SIEM/SOC detection catalogue.
- Added alternative patterns including secure web file exchange, controlled Microsoft 365 collaboration, provider-native exchange and automated partner integration.

### Architectural position

- Treat human-operated SFTP as controlled data egress, not merely an allowed network destination.
- Do not assume an allowlisted multi-tenant SFTP provider proves the intended recipient.
- Use endpoint DLP because the endpoint can inspect/classify the file before SSH encryption.
- Use provider-side recipient/account restrictions whenever available.
- Block general Internet SSH/SFTP and allow only approved users/devices to approved provider endpoints.
- For sensitive or recurring transfers, migrate from endpoint-direct SFTP to enterprise MFT or another centrally governed secure-transfer service.

## 2026-09-11 — Draft v0.1

### Added

- Established repository purpose and initial design position in `README.md`.
- Added `docs/enterprise-outbound-security.md` as the initial enterprise architecture/security draft.
- Defined default-deny principles for server/application Internet egress.
- Defined enterprise/protective DNS as a baseline control and documented why DNS filtering alone is insufficient.
- Compared unrestricted direct access, Layer-3/4 firewall/NAT, protective DNS, authenticated Layer-7 proxy/SWG, TLS inspection, cloud-native distributed egress, centralized egress hubs and private connectivity.
- Added risks and trade-offs for each approach.
- Added twenty baseline outbound security requirements (`OUT-01` through `OUT-20`).
- Added a decision matrix comparing direct, protective DNS and authenticated Layer-7 proxy approaches.
- Added a four-tier security model plus a controlled-direct exception tier.
- Added a Mermaid reference architecture.
- Added an application onboarding decision process.
- Added example application scenarios including SaaS API access, developer browsing, package retrieval, certificate pinning and mTLS.
- Added centralized-versus-distributed egress analysis.
- Added monitoring/detection use cases, governance roles and metrics.
- Added a phased implementation roadmap.
- Added standards/guidance references including NIST SP 800-207, NIST SP 1800-35, NIST SP 800-81r3, NSA encrypted DNS guidance, CISA Protective DNS guidance and Microsoft network/TLS inspection guidance.

### Initial architectural position

- Do not use unrestricted direct Internet access as the enterprise default for workloads.
- Use enterprise/protective DNS plus stateful egress enforcement as the normal baseline.
- Add authenticated Layer-7 proxy/SWG controls when identity, URL/content inspection, malware controls or DLP justify the additional complexity.
- Prefer private connectivity for sensitive strategic services where practical.
- Allow controlled direct egress as an explicit pattern when proxying/interception is incompatible or creates disproportionate performance/resilience risk.
- Centralize policy and telemetry; do not assume every packet must be backhauled to a single physical egress location.

## Candidate additions for future revisions

- Formal control mapping to NIST SP 800-53, CIS Controls and ISO 27001.
- Detailed cloud patterns for AWS, Azure and GCP.
- Kubernetes egress patterns and service-mesh/egress-gateway options.
- Detailed Secure Web Gateway / SASE architecture.
- DNS firewall reference architecture and bypass controls.
- Explicit workload identity patterns for machine-to-machine proxy access.
- Policy-as-code model and example rule schema.
- Egress request/approval workflow and sample request form.
- Exception and recertification workflow.
- Failure-mode analysis for DNS, proxy, firewall, WAN and cloud-region outages.
- Comparison of centralized versus regional/distributed egress cost and resilience.
- TLS inspection policy and bypass standard.
- QUIC/HTTP3, encrypted DNS and other modern protocol handling.
- Package repository, container registry and CI/CD egress standards.
- SIEM detection catalogue for outbound traffic.
- Reference diagrams for user, datacenter, cloud and hybrid patterns.
