# Cyber_Security_attacks

This repository contains a collection of security exploits and automated attack scripts implemented in C and crafted payloads for various web and network vulnerabilities. 

---

## Implemented Attacks

### 1. Web Application Attacks
* **Reflected XSS:** A crafted URL utilizing the `msg` parameter to redirect victim sessions and capture cookies.
* **Stored XSS:** A multi-part attack consisting of an attacker client that POSTs malicious scripts to a database and a listener that captures and utilizes stolen session cookies.
* **DOM-based XSS:** Exploitation of client-side script processing via URL fragments (`#user=...`) to execute malicious payloads.
* **Blind SQL Injection:** A boolean-based injection using a **Binary Search** algorithm to efficiently extract database tables, columns, and passwords under a 400-query limit.

### 2. Network & Infrastructure Attacks
* **HTTP Response Splitting:** An attack that injects CRLF sequences into parameters to desynchronize proxies and poison their cache with fake "200 OK" responses.
* **Kaminsky Attack:** (DNS Cache Poisoning) Exploiting the DNS protocol to redirect traffic by poisoning the resolver's cache.
* **HTTP Cache Poisoning:** Utilizing desynchronization to force a proxy to serve malicious content for legitimate pages.

### 3. Memory Corruption
* **Buffer Overflow:** Exploiting unsafe memory handling in C applications to overwrite return addresses and gain control of the execution flow.




