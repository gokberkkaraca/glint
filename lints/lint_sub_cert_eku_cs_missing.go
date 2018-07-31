package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
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

/*******************************************************************************************************
MRfCSC: Appendix B.3.F
extKeyUsage (required)
id-kp-codeSigning [RFC5280] MUST be present.
*******************************************************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subExtKeyUsageCodeSigningMissing struct{}

func (l *subExtKeyUsageCodeSigningMissing) Initialize() error {
	return nil
}

func (l *subExtKeyUsageCodeSigningMissing) CheckApplies(c *x509.Certificate) bool {
	return c.ExtKeyUsage != nil && util.IsCodeSigningCert(c)
}

func (l *subExtKeyUsageCodeSigningMissing) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	for _, kp := range c.ExtKeyUsage {
		if kp == x509.ExtKeyUsageCodeSigning {
			return &LintResult{Status: Pass}
		} else {
			continue
		}
	}
	// If expected value is not found
	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_eku_cs_missing",
		Description:   "id-kp-codeSigning MUST be present.",
		Citation:      "MRfCSC: Appendix B.3.F",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subExtKeyUsageCodeSigningMissing{},
	})
}
