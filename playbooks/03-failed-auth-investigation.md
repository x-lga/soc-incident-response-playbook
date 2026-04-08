# Playbook 03 - Failed Authentication Investigation

**Category:** Security Event - Authentication  
**ITIL 4 Priority:** P2 (single user / low volume) / P1 (account lockout wave or brute force) 

---

## Symptom Patterns

| Pattern | Likely Cause | Priority |
|---------|-------------|---------|
| Single user, multiple failures, same time | User forgot password / fat fingers | P3 |
| Single user, failures from multiple IPs | Credential stuffing attack | P2 |
| Many users, failures in short window | Password spray attack | P1 |
| Failures outside business hours | Potential brute force / stolen credentials | P2 |

---