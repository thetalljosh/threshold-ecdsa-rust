# threshold-ecdsa-rust

## ⚠️ SECURITY WARNING ⚠️

**🔴 CRITICAL VULNERABILITY: This implementation is vulnerable to key extraction attacks.**

This codebase lacks zero-knowledge range proofs in the MTA protocol, making it susceptible to the **Alpha-Rays attack** (ePrint 2021/1621). A malicious signing party can extract the full private key after just **8 signatures**.

**DO NOT USE IN PRODUCTION** with untrusted parties.

### Safe Use Cases
- ✅ Educational purposes (see `src/educational.rs`)
- ✅ Trusted single-organization deployments with audit logging
- ✅ Research and algorithm development

### Unsafe Use Cases  
- 🔴 Multi-party signing with potential adversaries
- 🔴 Cryptocurrency custody or asset management
- 🔴 Any adversarial threshold signature scenario

**For detailed vulnerability analysis and mitigations, see [SECURITY_ADVISORY.md](./SECURITY_ADVISORY.md)**

---