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
	"github.com/gokberkkaraca/glint/util"
)

/************************************************
MRfCSC: Appendix B.3.A
certificatePolicies:
	This extension MUST be present and SHOULD NOT be marked critical.
************************************************/

type cscCertificatePolicyMarkedCritical struct{}

func (l *cscCertificatePolicyMarkedCritical) Initialize() error {
	return nil
}

func (l *cscCertificatePolicyMarkedCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsCodeSigningCert(c) && util.IsExtInCert(c, util.CertPolicyOID)
}

func (l *cscCertificatePolicyMarkedCritical) Execute(c *x509.Certificate) *LintResult {
	if util.GetExtFromCert(c, util.CertPolicyOID).Critical {
		return &LintResult{Status: Warn}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_csc_certificate_policy_marked_critical",
		Description:   "certificatePolicies:policyIdentifier is required and should not be marked as critical",
		Citation:      "MRfCSC: Appendix B.3.A",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &cscCertificatePolicyMarkedCritical{},
	})
}
