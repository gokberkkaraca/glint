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
Either the value serverAuth [RFC5280] or anyExtendedKeyUsage MUST NOT be present.
*******************************************************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type subExtKeyUsageProhibitedUsage struct{}

func (l *subExtKeyUsageProhibitedUsage) Initialize() error {
	return nil
}

func (l *subExtKeyUsageProhibitedUsage) CheckApplies(c *x509.Certificate) bool {
	return c.ExtKeyUsage != nil && util.IsCodeSigningCert(c)
}

func (l *subExtKeyUsageProhibitedUsage) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	for _, kp := range c.ExtKeyUsage {
		if kp == x509.ExtKeyUsageAny || kp == x509.ExtKeyUsageServerAuth {
			// A bad usage was found, report and leave
			return &LintResult{Status: Error}
		} else {
			continue
		}
	}
	// If no bad usage was found, pass
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_eku_prohibited_usage",
		Description:   "Subscriber Certificate: extKeyUsage values MUST NOT be equal to anyExtendedKeyUsage or serverAuth.",
		Citation:      "MRfCSC: Appendix B.3.F",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subExtKeyUsageProhibitedUsage{},
	})
}
