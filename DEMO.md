
================================================================================
  CASE: clean.eml
================================================================================
╭───────────────────────────────────────────────────────────────────────╮
│ SENTINEL — AI Email Threat & Forensics Agent                          │
│ Investigating: /home/user/project/samples/clean.eml                   │
│ Kill-switch: press q / x / ESC to abort instantly. Ctrl+C also works. │
╰───────────────────────────────────────────────────────────────────────╯
thinking » Deterministic pipeline (no LLM) — running fixed investigation flow.
hash_evidence(email_path=/home/user/project/samples/clean.eml)
    → SHA-256=da8f87cf0c57e591…; 0 attachment(s)
parse_headers(email_path=/home/user/project/samples/clean.eml)
    → 2 Received hop(s); from=Bob Smith <bob@example.com>
resolve_origin(headers=<headers len=1282>)
    → origin=203.0.113.45 via client-ip in Received-SPF (conf=85%)
geolocate_ip(ip=203.0.113.45)
    → 203.0.113.45 -> None, None (conf=0%, r≈Nonekm)
check_tor_exit(ip=203.0.113.45)
    → 203.0.113.45: not Tor
extract_urls(body=<body len=152>)
    → 0 link(s), 0 suspicious
check_reputation(target=203.0.113.45, kind=ip)
    → 203.0.113.45 (ip): available=False
VERDICT: SAFE (100% confidence)
    FINAL VERDICT: SAFE    
┏━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Field      ┃ Value      ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Confidence │ 100%       │
│ Risk score │ 0/100      │
│ Evidence   │   • (none) │
└────────────┴────────────┘
Report saved: reports/report_clean_20260907-153846.md
Blockchain ledger: evidence/ledger.chain.json (length 1)


================================================================================
  CASE: phishing.eml
================================================================================
╭───────────────────────────────────────────────────────────────────────╮
│ SENTINEL — AI Email Threat & Forensics Agent                          │
│ Investigating: /home/user/project/samples/phishing.eml                │
│ Kill-switch: press q / x / ESC to abort instantly. Ctrl+C also works. │
╰───────────────────────────────────────────────────────────────────────╯
thinking » Deterministic pipeline (no LLM) — running fixed investigation flow.
hash_evidence(email_path=/home/user/project/samples/phishing.eml)
    → SHA-256=cc5498de98ac82d5…; 0 attachment(s)
parse_headers(email_path=/home/user/project/samples/phishing.eml)
    → 2 Received hop(s); from=PayPal Security <service@paypal.com>
resolve_origin(headers=<headers len=1151>)
    → origin=185.220.101.34 via client-ip in Received-SPF (conf=85%)
geolocate_ip(ip=185.220.101.34)
    → 185.220.101.34 -> None, None (conf=0%, r≈Nonekm)
check_tor_exit(ip=185.220.101.34)
    → 185.220.101.34: not Tor
extract_urls(body=<body len=515>)
    → 1 link(s), 1 suspicious
check_reputation(target=185.220.101.34, kind=ip)
    → 185.220.101.34 (ip): available=False
VERDICT: MALICIOUS (95% confidence)
                                               FINAL VERDICT: MALICIOUS                                                
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field      ┃ Value                                                                                                  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Confidence │ 95%                                                                                                    │
│ Risk score │ 95/100                                                                                                 │
│ Evidence   │   • parse_headers: SPF check failed (sender domain mismatch); DKIM neutral (no valid sender signature) │
│            │   • extract_urls: URL risk signals worth 60pts                                                         │
└────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Report saved: reports/report_phishing_20260907-153846.md
Blockchain ledger: evidence/ledger.chain.json (length 2)


================================================================================
  CASE: bec_gmail.eml
================================================================================
╭───────────────────────────────────────────────────────────────────────╮
│ SENTINEL — AI Email Threat & Forensics Agent                          │
│ Investigating: /home/user/project/samples/bec_gmail.eml               │
│ Kill-switch: press q / x / ESC to abort instantly. Ctrl+C also works. │
╰───────────────────────────────────────────────────────────────────────╯
thinking » Deterministic pipeline (no LLM) — running fixed investigation flow.
hash_evidence(email_path=/home/user/project/samples/bec_gmail.eml)
    → SHA-256=5077df6efa126341…; 0 attachment(s)
parse_headers(email_path=/home/user/project/samples/bec_gmail.eml)
    → 3 Received hop(s); from=CEO ExampleCorp <ceo.examplecorp@gmail.com>
resolve_origin(headers=<headers len=1556>)
    → origin=unrecoverable via fallback (conf=15%)
extract_urls(body=<body len=418>)
    → 0 link(s), 0 suspicious
    → content heuristic: urgency + secrecy + financial request (BEC pattern); possible executive impersonation tone
VERDICT: SUSPICIOUS (30% confidence)
                                               FINAL VERDICT: SUSPICIOUS                                                
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field      ┃ Value                                                                                                   ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Confidence │ 30%                                                                                                     │
│ Risk score │ 30/100                                                                                                  │
│ Evidence   │   • resolve_origin: sender origin unrecoverable (webmail relay); confidence lowered                     │
│            │   • content-heuristic: urgency + secrecy + financial request (BEC pattern); possible executive          │
│            │ impersonation tone                                                                                      │
└────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Report saved: reports/report_bec_gmail_20260907-153846.md
Blockchain ledger: evidence/ledger.chain.json (length 3)


================================================================================
  CASE: malware_attachment.eml
================================================================================
╭───────────────────────────────────────────────────────────────────────╮
│ SENTINEL — AI Email Threat & Forensics Agent                          │
│ Investigating: /home/user/project/samples/malware_attachment.eml      │
│ Kill-switch: press q / x / ESC to abort instantly. Ctrl+C also works. │
╰───────────────────────────────────────────────────────────────────────╯
thinking » Deterministic pipeline (no LLM) — running fixed investigation flow.
hash_evidence(email_path=/home/user/project/samples/malware_attachment.eml)
    → SHA-256=ec9e9fdcf7f67eb4…; 1 attachment(s)
parse_headers(email_path=/home/user/project/samples/malware_attachment.eml)
    → 2 Received hop(s); from=Accounts Payable <no-reply@badactor-evil.top>
resolve_origin(headers=<headers len=1087>)
    → origin=45.155.205.211 via client-ip in Received-SPF (conf=85%)
geolocate_ip(ip=45.155.205.211)
    → 45.155.205.211 -> None, None (conf=0%, r≈Nonekm)
check_tor_exit(ip=45.155.205.211)
    → 45.155.205.211: not Tor
extract_urls(body=<body len=106>)
    → 0 link(s), 0 suspicious
    → content heuristic: urgency + financial request
check_reputation(target=45.155.205.211, kind=ip)
    → 45.155.205.211 (ip): available=False
[CONFIRM_NEEDED] tool `static_file_scan` will touch files inside the sandbox.
    args: {"attachment_path": "evidence/attachments/pending/Invoice_00921.pdf"}
    Type 'yes' to approve, anything else to deny:     approved.
static_file_scan(attachment_path=evidence/attachments/pending/Invoice_00921.pdf)
    → sandboxed=False; ["ELF executable disguised as .pdf"]
VERDICT: MALICIOUS (75% confidence)
                                               FINAL VERDICT: MALICIOUS                                                
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field      ┃ Value                                                                                                  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Confidence │ 75%                                                                                                    │
│ Risk score │ 75/100                                                                                                 │
│ Evidence   │   • parse_headers: SPF check failed (sender domain mismatch); DKIM neutral (no valid sender signature) │
│            │   • content-heuristic: urgency + financial request                                                     │
│            │   • static_file_scan: attachment flags: ELF executable disguised as .pdf                               │
└────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Report saved: reports/report_malware_attachment_20260907-153846.md
Blockchain ledger: evidence/ledger.chain.json (length 4)

================================================================================
  BLOCKCHAIN LEDGER INTEGRITY CHECK
================================================================================
Ledger: evidence/ledger.chain.json -> {'valid': True, 'length': 4, 'broken_at': None}
