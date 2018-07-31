package lints

/*
 * ZLint Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

/************************************************
MRfCSC: Appendix B.3.A
certificatePolicies:
	This extension MUST be present and SHOULD NOT be marked critical.
************************************************/

type cscCertificatePolicyIdentifierMissing struct{}

func (l *cscCertificatePolicyIdentifierMissing) Initialize() error {
	return nil
}

func (l *cscCertificatePolicyIdentifierMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsCodeSigningCert(c) && util.IsExtInCert(c, util.CertPolicyOID)
}

func (l *cscCertificatePolicyIdentifierMissing) Execute(c *x509.Certificate) *LintResult {
	if len(c.PolicyIdentifiers) != 0 {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_csc_cert_policy_identifier_missing",
		Description:   "certificatePolicies:policyIdentifier is required",
		Citation:      "MRfCSC: Appendix B.3.A",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &cscCertificatePolicyIdentifierMissing{},
	})
}
