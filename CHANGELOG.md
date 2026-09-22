# Change Log

This file tracks material additions and changes to the Enterprise Outbound Security working drafts.

## 2026-09-22 — Decision checklist v0.2

### Added / changed

- Added `docs/Enterprise_Outbound_Egress_Decision_Checklist.xlsx` as a practical architecture-review workbook.
- Simplified the workbook from a weighted scoring model into a short checklist using mostly Yes/No and Low/Medium/High decisions.
- The checklist now produces a direct control recommendation: no general Internet, protective DNS + restrictive Layer-3/4, enhanced compensating controls, or Layer-7/application-aware enforcement.
- Added explicit checklist questions for human interactivity, fixed-purpose workloads, destination scope, arbitrary data selection, multi-tenant destinations, upload/data-sink capability, sensitive data, observability requirements, endpoint/workload hardening, service-native recipient controls and assume-breach abuse.
- Added a separate Layer-7 availability/compatibility check so proxy/SWG failure-domain risk is considered alongside its security benefit.
- Added a concise residual-risk statement covering the inability of DNS/L3-L4 telemetry to identify exact encrypted file/content, API action or logical tenant/recipient.
- Added a quick-reference sheet describing the intended use and residual risks of DNS/L3-L4, L7/SWG, service-native tenant controls, MFT and private/no-Internet patterns.

## 2026-09-22 — Draft v0.4

### Added

- Added a risk-tiered egress-control model that distinguishes interactive human behavior from tightly constrained fixed-purpose workloads.
- Added five suggested egress risk tiers, from constrained managed workloads through crown-jewel/regulated transfer use cases.
- Added explicit risk dimensions: human agency, destination variability, data access, protocol flexibility, software mutability, credential power, logical-destination ambiguity, compromise blast radius, availability criticality and required observability.
- Added a detailed comparison of human endpoint risk versus fixed-purpose managed server/workload risk.
- Documented when enterprise/protective DNS plus Layer-3/4 stateful egress controls can be an appropriate primary pattern for low-variability workloads.
- Explicitly documented the residual visibility gap when Layer-7 inspection is absent: the enterprise may know source, destination, timing and byte counts but may not know the exact file, URL/API method, data fields or logical SaaS tenant/account that received data.
- Documented why the visibility gap may still be an acceptable residual risk for a tightly managed fixed-purpose workload with a small capability envelope and strong compensating controls.
- Added an assume-breach overlay for managed workloads covering arbitrary IP/DNS access, abuse of approved SaaS/API destinations, data access, secret theft, tool execution, HTTPS tunnelling, bulk exfiltration, configuration manipulation and use of lateral egress relays.
- Added an assume-breach overlay for interactive human endpoints, highlighting abuse of legitimate SaaS, cloud storage, collaboration platforms, external tenants/accounts and approved transfer services.
- Added analysis of the incremental security value of Layer-7 filtering, including URL/API policy, identity, DLP, malware inspection, SaaS recognition and tenant restrictions.
- Added explicit residual limitations of Layer-7 controls, including mTLS/pinning, QUIC/gRPC/WebSockets/custom protocols, application-layer encryption, encrypted archives and abuse of otherwise-valid application transactions.
- Added a detailed Layer-7 proxy/SWG availability and security risk table covering outage, centralized blast radius, capacity, latency, TLS/certificate failures, proxy authentication, dynamic endpoints, protocol compatibility, state/session failover, provider outages, backhaul dependency and TLS-decryption concentration.
- Added explicit fail-open versus fail-closed analysis.
- Added a DNS/L3-L4 versus Layer-7 decision matrix for fixed APIs, multi-tenant services, mTLS/pinned applications, sensitive servers, users, SFTP, privileged endpoints and high-SLA applications.
- Added baseline requirements `OUT-21` (risk-tiered egress selection), `OUT-22` (residual visibility acceptance) and `OUT-23` (inline-control availability risk).

### Architectural position

- Interactive humans normally warrant stronger Layer-7 and endpoint data controls because they can dynamically choose data, applications, destinations, accounts and tenants.
- Fixed-purpose managed workloads may use DNS + Layer-3/4 egress enforcement without mandatory active Layer-7 proxying when their destinations, protocols, software, identities and data flows are tightly constrained.
- A non-human workload is not automatically low risk; sensitive data, broad privileges, arbitrary code execution or multi-tenant upload destinations can elevate it substantially.
- Under assume breach, the key question is whether an attacker can repurpose an approved destination as a C2 or exfiltration channel.
- Lack of Layer-7 inspection creates a known observability gap, but that gap can be an acceptable residual risk where the workload capability envelope is narrow and application/endpoint/provider telemetry is strong.
- Layer-7 proxying is itself a risk-bearing production dependency. Its security benefit must be balanced against availability, latency, protocol compatibility, certificate/key management, operational complexity and shared failure-domain risk.
- For business-critical fixed-purpose workloads, controlled direct egress with strong DNS/L3-L4, host, identity and application controls can be preferable to introducing an L7 dependency that provides little incremental security value.

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
