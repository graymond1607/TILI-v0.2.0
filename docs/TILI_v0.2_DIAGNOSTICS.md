# TILI v0.2 — Diagnostic detection and correlation

## Visual semantics
- **Red:** every matched diagnostic error in the Findings view. The rule severity (CRITICAL/HIGH/MEDIUM/LOW) remains separately available.
- **Orange:** an identified instance with one or more matched findings in the supplied logs.
- **Green:** the supplied logs contain events for the instance and no current rules matched. This is not a health guarantee.
- **Unknown:** no reliable instance identity or insufficient log coverage. Do not infer green from missing logs.

## Initial regex families
Network, Card Terminals, VPN, DNS, gSMC-K, SMC-B/SMC-K/HBA, Certificates, Hardware, Software, Security and General/Availability. Rules are stored in `data/knowledge_base.json`; each has a stable ID, source scope, category, regex, severity, description, recommendation and confidence note.

## Adding rules
1. Verify the signature against approved internal documentation and anonymised representative logs.
2. Prefer exact error identifiers or distinctive message fields over broad keywords.
3. Add positive and negative test cases.
4. Set source scope and component/version applicability where known.
5. Keep recommendations diagnostic and non-destructive.

## Identity and comparison
The parser extracts HSKP-style hostnames, UUID-shaped identifiers and cHSM numeric identifiers when explicitly present. Values are not interchangeable. A filename-derived HSKP label is a hint, not a verified UID. Host identity conflicts and multi-line context need dedicated product-specific parsers in subsequent iterations.

## Correlation limits
Current correlation groups timestamped findings by temporal proximity and reports per-instance error counts. It does not prove causal relationships, establish shared physical HSM topology, or guarantee synchronized clocks. Cross-device root-cause hypotheses require verified topology, clock-offset handling, change history and source-linked evidence.

## Security coverage warning
The included security expressions are starter indicators, not comprehensive security monitoring or an IDS. They can generate false positives and cannot determine whether an event is malicious. Preserve logs, follow internal incident response procedures and validate alerts with the security team.
