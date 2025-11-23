# Ava Guardian Production Deployment Guide

Comprehensive checklist and procedures for deploying Ava Guardian in production environments.

---

## Pre-Deployment Checklist

### ✅ Environment Verification

- [ ] Python 3.8+ installed
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] liboqs-python available (recommended for production)
- [ ] HSM accessible (if using hardware security)
- [ ] Network access to RFC 3161 TSA (if timestamping enabled)
- [ ] Sufficient disk space (1 GB minimum, 10 GB recommended)
- [ ] Backup procedures tested

### ✅ Security Audit

- [ ] Code review completed
- [ ] Dependency vulnerability scan passed
- [ ] Secrets management configured
- [ ] Access controls defined
- [ ] Audit logging enabled
- [ ] Incident response plan documented

### ✅ Performance Testing

- [ ] Benchmarks run and validated
- [ ] Load testing completed
- [ ] Resource limits configured
- [ ] Monitoring dashboards prepared

---

## Key Management Setup

### Option 1: Hardware Security Module (HSM)

**Recommended for production.**

```python
from dna_guardian_secure import generate_key_management_system
import os

# 1. Generate master secret
master_secret = os.urandom(32)

# 2. Store in HSM
# (Use your HSM library - example with PKCS#11)
# hsm.import_key(master_secret, label="ava-guardian-master")

# 3. Store HSM reference securely
# with open("/secure/config/hsm_key_id", "w") as f:
#     f.write(hsm_key_id)
```

**HSM Configuration Checklist**:
- [ ] FIPS 140-2 Level 3+ certified
- [ ] Backup HSM configured
- [ ] Access controls enforced
- [ ] Audit logging enabled
- [ ] Key ceremony documented

---

### Option 2: Encrypted Keystore

**For smaller deployments or testing.**

```python
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generate and encrypt keys
kms = generate_key_management_system("production")

# Encrypt with AESGCM
key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
aesgcm = AESGCM(key)

encrypted = aesgcm.encrypt(nonce, kms.master_secret, None)

# Save securely
keystore = {
    'nonce': nonce.hex(),
    'encrypted_secret': encrypted.hex()
}

keystore_path = Path("/secure/keystore.json")
keystore_path.write_text(json.dumps(keystore))
keystore_path.chmod(0o600)  # Owner read/write only
```

**Encrypted Keystore Checklist**:
- [ ] Strong password policy enforced
- [ ] File permissions restricted (600)
- [ ] Regular key rotation scheduled
- [ ] Backup encrypted separately
- [ ] Password stored in secure vault

---

## RFC 3161 Timestamping

### Enabling Trusted Timestamps

```python
# Configure TSA URL
TSA_URL = "https://freetsa.org/tsr"  # Or your organization's TSA

# Create package with timestamp
pkg = create_crypto_package(
    codes,
    helix_params,
    kms,
    author="production",
    use_rfc3161=True,
    tsa_url=TSA_URL
)
```

### TSA Options

| Provider | URL | Cost | Reliability |
|----------|-----|------|-------------|
| FreeTSA | https://freetsa.org/tsr | Free | Good |
| DigiCert | https://timestamp.digicert.com | Free | Excellent |
| Sectigo | https://timestamp.sectigo.com | Free | Excellent |

---

## 3R Monitoring Configuration

### Production Monitoring Setup

```python
from ava_guardian_monitor import AvaGuardianMonitor
import logging

# Configure logging
logging.basicConfig(
    filename="/var/log/ava-guardian-monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Create monitor with production settings
monitor = AvaGuardianMonitor(
    enabled=True,
    alert_retention=5000  # Keep last 5000 alerts
)

# Adjust sensitivity for production
monitor.timing.threshold = 3.0  # 3σ (conservative)
```

### Alert Handler

```python
def handle_security_alerts(monitor):
    """Check for critical alerts and respond."""
    report = monitor.get_security_report()
    
    # Check for critical timing anomalies
    critical_timing = [
        a for a in report['recent_alerts']
        if a['type'] == 'timing' and a['anomaly'].severity == 'critical'
    ]
    
    if critical_timing:
        logging.critical(f"CRITICAL TIMING ANOMALY: {len(critical_timing)} alerts")
        # Send to SIEM, page security team, etc.
```

---

## Key Rotation

### Quarterly Key Rotation

```python
import datetime

def should_rotate_keys(kms, rotation_days=90):
    """Check if keys should be rotated."""
    key_age = datetime.datetime.now() - kms.creation_date
    return key_age.days >= rotation_days

def rotate_keys(old_kms, author):
    """Rotate keys while preserving verification capability."""
    # 1. Generate new KMS
    new_kms = generate_key_management_system(author)
    
    # 2. Archive old keys (for verification)
    # Save old public keys for historical verification
    
    # 3. Update active key ID
    # update_active_key_id(new_kms.key_id)
    
    # 4. Log rotation event
    logging.info(f"Key rotation completed")
    
    return new_kms
```

---

## Backup and Recovery

### Backup Procedures

```python
def backup_keys():
    """Backup keys to secure location."""
    # 1. Encrypt keys with backup key
    # 2. Store in multiple locations
    # 3. Verify backup integrity
    pass

# Schedule daily backups at 1 AM
# Use cron or system scheduler
```

### Recovery Procedures

```python
def recover_from_backup(backup_file):
    """Recover KMS from encrypted backup."""
    # 1. Load encrypted backup
    # 2. Decrypt using backup key
    # 3. Reconstruct KMS
    # 4. Verify integrity
    pass
```

---

## Security Hardening

### System-Level Security

```bash
# 1. Restrict file permissions
chmod 700 /opt/ava-guardian
chmod 600 /secure/keystore.json

# 2. Create dedicated user
useradd -r -s /bin/false ava-guardian
chown -R ava-guardian:ava-guardian /opt/ava-guardian

# 3. Configure firewall (if service-based)
# ufw allow from trusted_network to any port 8443
```

### Application-Level Security

```python
# 1. Validate all inputs
def create_package_validated(codes, helix_params, kms):
    """Create package with input validation."""
    # Validate codes format
    # Validate helix params ranges
    # Validate KMS integrity
    return create_crypto_package(codes, helix_params, kms)

# 2. Rate limiting
from functools import wraps
import time

def rate_limit(max_calls_per_minute):
    def decorator(func):
        calls = []
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            calls[:] = [c for c in calls if c > now - 60]
            if len(calls) >= max_calls_per_minute:
                raise Exception("Rate limit exceeded")
            calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

---

## Disaster Recovery

### Scenarios and Procedures

**Scenario 1: Key Compromise**
1. Immediately rotate all keys
2. Revoke compromised key IDs
3. Re-sign all packages with new keys
4. Notify affected parties

**Scenario 2: HSM Failure**
1. Activate backup HSM
2. Restore keys from encrypted backup
3. Verify key integrity
4. Resume operations

**Scenario 3: Performance Degradation**
1. Disable 3R monitoring temporarily
2. Scale horizontally (add nodes)
3. Investigate bottleneck
4. Optimize or upgrade resources

---

## Deployment Checklist

### Pre-Production

- [ ] All tests passing
- [ ] Benchmarks validated
- [ ] Security audit completed
- [ ] Backup procedures tested
- [ ] Monitoring configured
- [ ] Documentation reviewed

### Production

- [ ] Keys generated securely
- [ ] Keystore encrypted and backed up
- [ ] Application deployed
- [ ] Monitoring active
- [ ] Logs shipping to SIEM
- [ ] Alerts configured
- [ ] On-call rotation established

### Post-Deployment

- [ ] Smoke tests passed
- [ ] Performance validated
- [ ] Security scan passed
- [ ] Backup verified
- [ ] Documentation updated

---

## Contact and Support

**Security Issues**: steel.secadv.llc@outlook.com  
**Documentation**: GitHub Repository  

---

*Last Updated: 2025*  
*Version: 1.0.0*  
*Steel Security Advisors LLC*
