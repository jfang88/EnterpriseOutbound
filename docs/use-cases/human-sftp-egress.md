# Use Case — Human-Operated SFTP Data Transfer to External Services

**Status:** Working draft  
**Version:** 0.1  
**Last updated:** 2026-09-22  
**Parent standard:** [Enterprise Outbound Network Security](../enterprise-outbound-security.md)

## 1. Scenario

Enterprise users sometimes need to transfer files to an external organization using SFTP.

The current-state assumption is:

- There is no centralized enterprise SFTP / Managed File Transfer (MFT) service.
- A human runs an SFTP client from an enterprise-managed endpoint.
- The external SFTP service may be a multi-tenant managed service used by many organizations.
- The enterprise knows and approves the external SFTP hostname/service.
- Different subscribers/customers of that service may share the same hostname, IP ranges and SFTP infrastructure.
- Some transfers may contain confidential or regulated information.
- A centralized enterprise transfer capability may be introduced later.

This use case is materially different from a server application connecting to a fixed external API. The human can select both the local data and, depending on the external service, the destination account/folder/customer.

## 2. Core security issue

**Allowing an SFTP hostname is not equivalent to authorizing the logical recipient of the data.**

A network firewall may be able to establish that:

> Managed endpoint A connected to approved SFTP service B over TCP/22.

That does not necessarily establish that:

> Approved user A transferred approved file X to approved partner account Y.

SFTP runs over SSH. SSH user authentication and subsequent file-transfer activity occur inside the protected SSH transport. After key exchange, normal network controls that do not terminate SSH generally cannot see the SFTP username, remote path, file name or file contents.

This creates a multi-tenant destination problem:

```text
                         APPROVED NETWORK DESTINATION
                                  |
                                  v
                        sftp.transfer.example
                                  |
                    +-------------+-------------+
                    |             |             |
                    v             v             v
              Partner A       Partner B     Subscriber Z
              APPROVED         maybe         UNAPPROVED
                               approved
```

A firewall allowlist for `sftp.transfer.example:22` can restrict the user to the transfer provider, but may not distinguish Partner A from Subscriber Z.

This is therefore a **destination-within-a-destination** problem.

## 3. Threat scenarios

| Threat | Example | Primary concern |
|---|---|---|
| Accidental misdirection | User selects the wrong remote account/folder at the approved SFTP provider | Confidentiality breach |
| Malicious insider exfiltration | User has or creates access to another subscriber/account on the same transfer service | Approved network destination becomes an exfiltration channel |
| Compromised endpoint | Malware uses an installed SFTP/SSH client or stolen key to upload files | Data theft and credential abuse |
| Compromised SFTP credentials | Attacker uses legitimate enterprise credentials to send or retrieve information | Misuse may resemble normal transfer activity |
| Excessive transfer | User sends far more data than normal to an otherwise valid partner | Bulk exfiltration |
| Sensitive-file selection | User sends files with prohibited labels/classification | Policy violation |
| Staging and obfuscation | Sensitive files are compressed, renamed or encrypted before transfer | Reduced DLP/content visibility |
| Alternate client | User uses `scp`, `ssh`, `curl`, PowerShell, Python or a portable tool instead of the approved client | Endpoint policy bypass |
| Alternate SSH service | User connects to a personal VPS or other SSH server | Direct exfiltration |
| SSH tunnelling | An SSH-capable service permits forwarding/tunnelling rather than SFTP-only access | Bypass of other network controls |
| Provider-side lateral access | One provider account can access multiple customer mailboxes/directories | Recipient authorization failure |
| Host-key failure or substitution | User accepts an unexpected SSH host key | Potential interception or wrong destination |
| Weak transfer audit | Network logs show bytes to the provider but not file/recipient detail | Detection and investigation gaps |

## 4. Current-state risk assessment

### 4.1 Known SFTP destination is useful but insufficient

Restricting outbound SSH/SFTP to an approved provider materially reduces risk compared with unrestricted TCP/22.

It can prevent:

- Direct SFTP/SSH to arbitrary Internet hosts.
- Simple use of a personal VPS for exfiltration.
- Many commodity SSH-based command-and-control paths.

However, if the provider is multi-tenant, the control may stop at the provider boundary.

The residual risk is that an approved provider can be used to reach an unapproved **logical destination**.

### 4.2 SFTP encryption limits network inspection

SFTP is carried inside SSH. Without terminating/brokering the SSH session, network security controls generally have visibility into:

- Source and destination IP.
- Destination port.
- Connection time and duration.
- Bytes sent/received.
- DNS resolution, if enterprise DNS is used.
- Some SSH protocol/fingerprint metadata.

They normally do **not** have reliable visibility into:

- Authenticated SFTP username.
- Remote customer/subscriber identity.
- Remote folder/path.
- File names.
- File content/classification.

A conventional HTTP/HTTPS Secure Web Gateway is therefore not automatically an SFTP control point.

### 4.3 Known recipient credentials are still not a complete control

Even where the enterprise provisions a credential for the approved partner account:

- The user might possess another credential.
- A shared account might be abused by multiple people.
- The provider may permit account-to-account transfers.
- The user may create or request additional remote accounts.
- A compromised endpoint may steal or use the approved credential.
- The approved partner account itself may be compromised.

The design should therefore combine **recipient controls, endpoint controls, data controls, network controls and monitoring**.

---

## 5. Recommended interim architecture — no centralized SFTP service

Until an enterprise MFT capability exists, use a layered pattern.

```text
+------------------------------+
| Managed user endpoint        |
|                              |
| - EDR                        |
| - Endpoint DLP               |
| - App Control                |
| - Approved SFTP client only  |
| - Managed SSH configuration  |
+--------------+---------------+
               |
               | SFTP / SSH
               v
+------------------------------+
| Enterprise egress controls   |
|                              |
| - Default deny TCP/22        |
| - User/device scoped rule    |
| - Approved provider only     |
| - Enterprise DNS             |
| - Flow / volume telemetry    |
+--------------+---------------+
               |
               | fixed enterprise egress IP
               v
+------------------------------+
| External SFTP provider       |
|                              |
| - Source IP allowlist        |
| - Named user / strong auth   |
| - Approved partner account   |
| - Restricted virtual folder  |
| - Provider audit logs        |
+------------------------------+
```

### Minimum interim position

1. Block general outbound TCP/22 from normal user networks.
2. Permit SFTP only for approved users/devices and approved provider endpoints.
3. Allow only the SFTP protocol/use case; do not grant general SSH access merely because SFTP is required.
4. Use enterprise-managed SFTP client software.
5. Use endpoint DLP to monitor/restrict protected files accessed by the SFTP client where the endpoint platform supports it.
6. Use application control to limit alternative transfer clients/tools where practical.
7. Use per-user or tightly controlled enterprise credentials, not broadly shared accounts.
8. Pin/manage expected SSH host keys.
9. Have the provider restrict the enterprise account to the intended partner/folder where the service supports it.
10. Source-IP allowlist the enterprise's egress addresses at the provider where practical.
11. Collect endpoint, firewall and provider-side logs.
12. Alert on unusually large, unusual-time or first-seen transfers.
13. Require documented approval for the partner, data classification and transfer purpose.
14. Recertify the access and remove it when the business relationship ends.

---

## 6. Endpoint controls

Endpoint controls are particularly important because the endpoint sees the file **before SSH encrypts it**.

### 6.1 Endpoint DLP

Endpoint DLP should be evaluated as the primary content-aware compensating control for direct human SFTP.

Where supported, configure policy so that:

- The approved SFTP client is treated as a controlled/restricted application.
- Sensitive or highly classified files generate an audit, block-with-override or block action.
- Overrides require business justification and are logged.
- DLP events feed the SIEM.
- Policies consider labels, sensitive information types and other enterprise data classifications.

Microsoft Purview Endpoint DLP, for example, supports restricted apps/app groups and can audit or restrict a DLP-protected file when a listed application accesses it.

Important limitation:

> Endpoint DLP controls the interaction between the local file and application. It does not, by itself, prove which subscriber/account inside a multi-tenant SFTP service received the file.

DLP capability should be validated against the actual SFTP client and file-handling workflow before relying on it as a preventative control.

### 6.2 Application control

Use application control to reduce alternate transfer paths.

Examples:

- Allow only approved/signed SFTP client versions.
- Restrict portable/unmanaged SFTP utilities.
- Restrict `scp`, interactive `ssh`, unapproved `curl` builds and scripting runtimes for user populations that do not need them.
- Prevent arbitrary unsigned binaries from running from user-writable directories.
- Use WDAC/App Control for Business, AppLocker, MDM controls or equivalent endpoint controls as appropriate.

Do not treat this as absolute prevention. General-purpose scripting environments and browser/cloud services can provide other exfiltration mechanisms.

### 6.3 Endpoint firewall / network protection

Endpoint network controls can reinforce the central firewall by:

- Blocking outbound TCP/22 except to approved provider IPs where stable.
- Restricting the rule to the approved application executable where the OS supports reliable per-application rules.
- Blocking known unapproved SSH/SFTP destinations.
- Generating local telemetry for attempted bypasses.

Microsoft Defender for Endpoint custom network indicators can block IP/domain destinations for non-browser processes when Network Protection is enabled, but these controls should complement rather than replace the enterprise egress firewall.

### 6.4 EDR detections

Useful endpoint detections include:

- SFTP/SSH client launched by an unusual parent process.
- SFTP client accessing a high volume of sensitive files.
- Creation of large ZIP/7z/RAR archives followed by SFTP.
- Creation of password-protected/encrypted archives followed by SFTP.
- First use of `ssh.exe`, `scp.exe`, portable FileZilla/WinSCP or similar tool by a user.
- Command-line SSH/SCP from Office applications, browsers or scripting hosts.
- Credential/key file access followed by outbound SSH.
- New or changed `known_hosts` entries.
- Transfer activity outside normal business hours.
- Abnormally large outbound byte counts.

### 6.5 Local staging controls

For higher-risk transfers, require users to copy files into an approved **transfer staging folder** first.

The staging workflow can provide:

- DLP classification.
- Malware scanning.
- Approval.
- File hash.
- Business case / ticket association.
- Retention period.
- Evidence of exactly what was approved.

This is a useful precursor to a future centralized MFT service.

---

## 7. Network controls

### 7.1 Default-deny SSH/SFTP

The normal user network should not have open Internet-wide TCP/22.

Recommended rule shape:

```text
Source:
  approved managed device/user population

Destination:
  approved SFTP provider FQDN/IP set

Protocol:
  TCP

Port:
  22 (or documented provider-specific SFTP port)

Action:
  allow + log

Everything else:
  deny
```

Where firewall technology supports identity-aware policy, bind the rule to the relevant users/devices rather than an entire subnet.

### 7.2 Enterprise DNS

Require enterprise DNS resolution for the approved SFTP hostname.

Protective DNS can:

- Detect malicious provider lookalike domains.
- Log resolution.
- Prevent many unapproved domains.

But it cannot determine the SFTP account/recipient after the connection reaches an approved multi-tenant service.

### 7.3 Fixed egress IP

Use a stable enterprise NAT/egress address where practical so the external provider can allowlist the enterprise as a source.

This reduces the usefulness of stolen SFTP credentials from unmanaged Internet locations, although it does not prevent misuse from a compromised enterprise endpoint.

### 7.4 Flow analytics

Because payload inspection is limited, metadata becomes important.

Monitor:

- Bytes sent per user/device/session.
- Number and duration of sessions.
- New source device.
- New provider IP.
- Transfers outside expected hours.
- Sudden changes from the user's baseline.
- High upload-to-download ratio.
- Repeated failed connections/authentication where provider logs are available.

Flow analytics is useful for detection but cannot reliably distinguish legitimate large business transfers from exfiltration without business and endpoint context.

### 7.5 SSH-aware firewall/IPS

An SSH-aware firewall may provide protocol identification, version/fingerprint information and some policy enforcement.

However, unless the control terminates/brokers SSH, do not assume it can inspect file contents or enforce the remote SFTP subscriber.

---

## 8. External SFTP provider controls

The enterprise should treat provider-side configuration as part of its outbound security design.

Prefer services that support:

- Dedicated enterprise tenant/account.
- Named users rather than shared credentials.
- Per-user SSH keys or stronger authentication.
- MFA for management/admin interfaces where applicable.
- Source IP allowlisting.
- Partner/recipient allowlists.
- Virtual folders/chroot-style isolation.
- No shell access.
- No SSH port forwarding/tunnelling.
- No ability for end users to create arbitrary external recipients.
- Strong separation between customer/subscriber areas.
- Detailed audit logs.
- File names, timestamps, user identities and remote destination records in audit events.
- API/syslog/SIEM export.
- Alerting and quotas.
- Short-lived or managed credentials where supported.

A particularly valuable provider-side control is:

> **Bind the enterprise's SFTP identity to the approved partner/folder so it cannot address other subscribers on the platform.**

If the provider cannot enforce this, the residual multi-tenant exfiltration risk should be documented.

---

## 9. Comparison — SFTP exfiltration vs Microsoft 365 external-tenant exfiltration

The two problems share the same architectural pattern:

> A trusted network/service endpoint may contain many logical destinations, only some of which are approved.

| Control question | Multi-tenant SFTP service | Microsoft 365 |
|---|---|---|
| Can DNS/firewall confirm the service? | Yes | Yes |
| Does service allowlisting prove the recipient tenant/account? | Usually no | No |
| Does normal network inspection see logical recipient? | Usually no; SSH encrypts authentication/file activity | Sometimes at Layer 7, but Microsoft-aware controls are preferable |
| Native tenant/recipient restriction | Provider-dependent and often limited | Entra tenant restrictions / cross-tenant controls provide tenant-aware enforcement for supported scenarios |
| Content-aware DLP | Best placed at endpoint or transfer gateway unless provider offers DLP | Purview/Endpoint DLP and Microsoft 365 service controls can provide deeper integration |
| User/app identity telemetry | Endpoint + provider logs required | Rich identity/service audit telemetry available |
| Network-only prevention of wrong logical destination | Weak | Weak without tenant-aware policy |
| Central policy enforcement | Requires provider control or enterprise gateway/MFT | Microsoft identity/service controls can enforce tenant policy |
| Data-plane awareness | Limited unless SSH is brokered/terminated | Supported Microsoft controls can operate at authentication and, for supported services, data plane |
| Residual risk | Other subscriber/account at approved host; stolen creds; encrypted archive; provider compromise | Approved/guest tenants, allowed external collaboration, unsupported paths, token/account misuse, personal/anonymous paths depending policy |

### Key lesson from Microsoft 365

Simply allowing Microsoft 365 endpoints would not be considered sufficient if the enterprise wants to prevent users from signing into arbitrary external tenants.

Microsoft provides tenant-aware controls such as Entra tenant restrictions v2 because **network destination is not the same as logical tenant authorization**.

The same principle should be applied to SFTP:

- If the SFTP provider can enforce recipient/account restrictions, use them.
- If it cannot, the enterprise needs stronger endpoint controls or an intermediary transfer service to close the gap.
- A firewall rule for the provider hostname should not be described as a complete data-exfiltration control.

---

## 10. Control options and trade-offs

| Pattern | Prevention strength | Recipient control | Content visibility | Operational overhead | Comments |
|---|---:|---:|---:|---:|---|
| Direct endpoint SFTP + open Internet TCP/22 | Low | Low | Low | Low | Not recommended |
| Direct endpoint SFTP + destination firewall allowlist | Moderate | Low | Low | Low/Medium | Stops arbitrary hosts but not other subscribers on approved service |
| Destination allowlist + endpoint DLP + app control | Medium/High | Low/Medium | Medium/High before encryption | Medium | Strong interim pattern; still weak if provider cannot bind recipient |
| Dedicated locked-down transfer VDI/workstation | High | Medium | High at staging endpoint | Medium/High | Useful interim solution for sensitive or infrequent transfers |
| SSH/SFTP proxy/broker | High | Medium/High | Potentially high if terminating session | High | Can add user/session/file logging; creates trust, key and HA complexity |
| Provider-native enterprise tenant + recipient restrictions | High | High if supported | Provider-dependent | Medium | Very effective without full enterprise MFT if provider has mature controls |
| Enterprise Managed File Transfer gateway | Very high | High | High | High | Preferred strategic solution for recurring/sensitive external transfer |
| Secure enterprise web file exchange | High | High | High | Medium | Often better UX than SFTP for human-to-human ad hoc sharing |
| Automated application-to-partner transfer | Very high | High | High | Medium/High initially | Removes human destination selection for recurring workflows |

---

## 11. Dedicated transfer workstation / VDI as an interim high-security option

Where the transfer is sensitive but a full MFT platform does not yet exist, consider a managed transfer VDI or jump workstation.

Pattern:

```text
Normal workstation
      |
      | place approved file in controlled staging location
      v
DLP / malware scan / approval
      |
      v
Locked-down transfer VDI
      |
      | approved SFTP client only
      | destination allowlist
      v
Approved external SFTP service
```

Controls can include:

- No general Internet browsing.
- No local admin.
- No arbitrary software install.
- Only approved SFTP client.
- Clipboard/drive-redirection restrictions where practical.
- SFTP destination allowlist.
- Central credential management.
- Session recording where appropriate.
- DLP on staging.
- EDR and enhanced logging.

Trade-off: this adds user friction and support overhead. It is best suited to high-risk or relatively infrequent transfers.

---

## 12. Strategic target — enterprise Managed File Transfer

A centralized MFT service is the preferred long-term pattern when SFTP is a recurring business requirement.

The strategic model changes the trust boundary:

```text
User
 |
 | authenticated enterprise portal / managed staging
 v
+---------------------------------------+
| Enterprise MFT / Secure Transfer Hub  |
|                                       |
| - SSO / MFA                           |
| - DLP / classification                |
| - Malware scanning                    |
| - Recipient / partner allowlist       |
| - Approval workflow                   |
| - File hash / immutable audit trail   |
| - Retention / expiry                  |
| - Key / credential management         |
| - Transfer quotas / limits            |
| - SIEM integration                    |
+------------------+--------------------+
                   |
                   | enterprise-controlled SFTP
                   v
            Approved partner/provider
```

### MFT capabilities to require

- Enterprise SSO and MFA for users.
- Per-partner definitions.
- Approval before new partner onboarding.
- Users choose only from approved partner records rather than typing arbitrary hosts/accounts.
- DLP/content classification before release.
- Malware scanning.
- Optional manual approval for high classifications.
- Immutable transfer audit.
- File hash and transaction ID.
- Automated retention/deletion of staging files.
- Managed SSH keys/secrets.
- Host-key verification.
- Source IP consistency.
- Rate/volume limits.
- Separation of sender, approver and platform administrator for high-risk flows.
- Provider/API integrations.
- High availability and disaster recovery.
- Ability to disable a partner centrally.
- SIEM/SOC integration.

### Security benefit

The MFT platform can make the security decision at the correct abstraction level:

> **User X may send approved file Y to approved partner Z for approved business purpose Q.**

A basic firewall cannot express that policy.

---

## 13. Other enterprise alternatives

### 13.1 Secure web file exchange

For human-to-human file sharing, a secure enterprise file exchange portal may be preferable to SFTP.

Potential advantages:

- Easier SSO/MFA.
- Recipient email/domain restrictions.
- Expiring links.
- Download controls.
- Watermarking.
- DLP.
- Malware scanning.
- Better user experience.
- Better audit trails.

This can reduce demand for desktop SFTP clients.

### 13.2 Microsoft 365 / SharePoint / OneDrive external collaboration

Where partner requirements allow, controlled Microsoft 365 external sharing can provide:

- Entra identity controls.
- Guest/B2B collaboration.
- Tenant/cross-tenant restrictions.
- Sensitivity labels and DLP.
- Sharing expiry and access reviews.
- Microsoft 365 audit telemetry.

This is not automatically lower risk than SFTP. The security outcome depends on external-sharing policy, tenant restrictions, labels, anonymous-link policy and partner governance.

### 13.3 Automated partner integration

For recurring transfers, replace manual human upload with:

- Scheduled MFT job.
- Partner API.
- Service-to-service SFTP account.
- Message/file integration platform.

This reduces:

- Wrong-recipient mistakes.
- Local credential exposure.
- User-driven destination changes.
- Ad hoc handling.

### 13.4 Provider-native managed exchange

If the existing external SFTP provider offers enterprise controls, it may be possible to improve security without immediately deploying an internal MFT platform.

Require evidence that the provider can restrict the enterprise tenant/users to specifically approved partners and generate sufficient audit logs.

---

## 14. Recommended policy position

### Short term

Permit human SFTP only as a controlled exception using:

- Managed endpoints.
- Approved users.
- Approved SFTP client.
- Endpoint DLP.
- Application control where practical.
- Default-deny Internet SSH/SFTP.
- Approved provider destination only.
- Provider source-IP allowlisting.
- Per-user credentials/keys.
- Managed host keys.
- Provider-side partner/folder restriction where supported.
- Central logging and volume/anomaly detection.
- Periodic recertification.

### Medium term

For sensitive transfers:

- Introduce a controlled staging workflow.
- Consider a dedicated transfer VDI/workstation.
- Obtain provider audit logs.
- Require recipient/account restrictions from the provider.
- Correlate file/DLP events with network and provider transfer events.

### Strategic target

Implement an enterprise secure transfer/MFT capability and move human users away from direct SFTP.

The endpoint should ideally no longer need direct Internet TCP/22. Users authenticate to the enterprise transfer platform, select an approved partner, and the platform performs the external transfer.

---

## 15. Proposed enterprise requirements

### SFTP-01 — Default deny

Outbound SSH/SFTP from user and server networks must be denied by default unless explicitly approved.

### SFTP-02 — Approved user/device

Human-operated SFTP must originate only from managed devices and approved users.

### SFTP-03 — Approved client

Human SFTP must use enterprise-approved software. Alternative SSH/SFTP transfer clients should be restricted where practical.

### SFTP-04 — Destination restriction

Network policy must restrict SFTP to approved provider endpoints and required ports.

### SFTP-05 — Logical recipient

Approval of an SFTP provider hostname does not constitute approval of every account/subscriber reachable through that provider.

The business/security design must identify the intended logical partner/account and, where supported, enforce that relationship provider-side or through an enterprise gateway.

### SFTP-06 — Data control

Sensitive data transfers must be subject to endpoint DLP, controlled staging, gateway DLP or equivalent content-aware controls appropriate to the data classification.

### SFTP-07 — Authentication

Shared SFTP credentials should be avoided. Use named identities or tightly controlled service identities and managed SSH keys/secrets.

### SFTP-08 — Host identity

Expected SSH host keys must be validated and managed. Users should not routinely accept unexpected host-key changes.

### SFTP-09 — Provider restrictions

Where technically available, provider-side policy should restrict:

- Enterprise source IP.
- SFTP identity.
- Partner/recipient.
- Remote folder.
- Protocol/subsystem.
- Shell/port-forwarding capability.

### SFTP-10 — Audit

The enterprise must be able to determine, to the greatest practical extent:

- Who initiated the transfer.
- From which managed device.
- When.
- To which provider and logical partner/account.
- What file was transferred, or at least its name/hash/classification.
- Transfer size.
- Whether DLP or approval policy was triggered.

### SFTP-11 — Monitoring

Large, unusual, first-seen and after-hours transfers should be detectable.

### SFTP-12 — Strategic migration

Recurring or sensitive human SFTP use cases should be candidates for migration to enterprise MFT, secure file exchange or automated partner integration.

---

## 16. Detection catalogue

Candidate SIEM/SOC detections:

1. TCP/22 to any destination not on the approved SFTP list.
2. Approved SFTP provider accessed by a user/device not assigned to the service.
3. First SFTP/SSH connection by a user or endpoint.
4. Large increase in outbound bytes to the provider.
5. Large transfer outside normal business hours.
6. SFTP client accesses DLP-protected file.
7. DLP override followed by outbound SFTP connection.
8. Archive/encryption utility followed by SFTP.
9. `ssh.exe` / `scp.exe` / scripting runtime reaching the approved provider when only the GUI client is approved.
10. New SSH host key or changed `known_hosts` entry.
11. Provider login from a non-enterprise source IP.
12. Provider audit shows unexpected remote account/folder.
13. Multiple failed provider authentication attempts followed by successful transfer.
14. Former employee or expired access group still generating provider activity.
15. Transfer to an approved provider with no corresponding business ticket/approved staging event for high-classification data.

---

## 17. Decision guidance

Use direct endpoint SFTP only when all of the following are acceptable:

- The use case is understood and approved.
- Endpoint DLP/application controls provide sufficient protection for the data.
- The provider destination can be tightly restricted.
- Provider-side controls adequately constrain the remote account/partner, **or** the residual logical-recipient risk is formally accepted.
- Transfer audit is sufficient for investigation.
- The volume/frequency does not justify automation/MFT.

Prefer MFT/secure exchange when:

- Transfers are recurring.
- Data is confidential/regulated.
- Many users or partners are involved.
- Approval is required.
- Recipient mistakes would have high impact.
- Provider-side tenant/account restrictions are weak.
- Strong evidence/non-repudiation is required.
- Credentials need centralized lifecycle management.

---

## 18. References

- RFC 4252 — The Secure Shell (SSH) Authentication Protocol  
  https://www.rfc-editor.org/rfc/rfc4252

- RFC 4253 — The Secure Shell (SSH) Transport Layer Protocol  
  https://www.rfc-editor.org/rfc/rfc4253

- Microsoft Purview — Configure Endpoint DLP settings; restricted apps and app groups  
  https://learn.microsoft.com/en-us/purview/dlp-configure-endpoint-settings

- Microsoft Entra — Tenant restrictions v2  
  https://learn.microsoft.com/en-us/entra/external-id/tenant-restrictions-v2

- Microsoft Defender for Endpoint — Network Protection and custom indicators  
  https://learn.microsoft.com/en-us/defender-endpoint/network-protection

- Microsoft App Control for Business  
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/
