package main

// refreshXRecovery consults only attempts inherited at startup. This process's
// own selected attempts hold their identity lane until report completion.
// A journal's local account name cannot prove a changed session's old identity;
// unresolved or missing bindings therefore block X conservatively.
func (p *servicePool) refreshXRecovery() {
	p.xRecoveryIdentities = map[string]bool{}
	p.xRecoveryUnknown = false
	if p.xRecovery == nil {
		return
	}
	records, err := p.xRecovery()
	if err != nil {
		p.xRecoveryUnknown = true
		return
	}
	for _, record := range records {
		if record.NoProvider {
			continue
		}
		if record.ProviderService == "codex" || record.ProviderService == "web" {
			continue
		}
		if record.ProviderService != "x_read" || record.ProviderAccountID == "" {
			p.xRecoveryUnknown = true
			continue
		}
		a := p.accounts["x_read:"+record.ProviderAccountID]
		if a == nil || a.removed || a.identity.ID == "" {
			p.xRecoveryUnknown = true
			continue
		}
		// Recovery records intentionally lack private provider identity stamps.
		// Even a reused local name cannot establish independent replacement quota.
		p.xRecoveryUnknown = true
		p.xRecoveryIdentities[a.identity.ID] = true
	}
}

func (p *servicePool) xRecoveryHolds(a *pooledAccount) bool {
	return p.xRecoveryUnknown || p.xRecoveryIdentities[a.identity.ID]
}
