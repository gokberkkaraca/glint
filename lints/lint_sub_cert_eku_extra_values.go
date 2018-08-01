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

 // TODO This lint is changed to check if the certificate is a code signing certificate or not, document properly
/*******************************************************************************************************
BRs: 7.1.2.3
extKeyUsage (required)
Either the value id-kp-serverAuth [RFC5280] or id-kp-clientAuth [RFC5280] or both values MUST be present. id-kp-emailProtection [RFC5280] MAY be present. Other values SHOULD NOT be present.
*******************************************************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type subExtKeyUsageLegalUsage struct{}

func (l *subExtKeyUsageLegalUsage) Initialize() error {
	return nil
}

func (l *subExtKeyUsageLegalUsage) CheckApplies(c *x509.Certificate) bool {
	return c.ExtKeyUsage != nil && util.IsCodeSigningCert(c)
}

func (l *subExtKeyUsageLegalUsage) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	for _, kp := range c.ExtKeyUsage {
		if kp == x509.ExtKeyUsageMicrosoftDocumentSigning || kp == x509.ExtKeyUsageMicrosoftLifetimeSigning || kp == x509.ExtKeyUsageEmailProtection || kp == x509.ExtKeyUsageCodeSigning{
			continue
		} else {
			// A bad usage was found, report and leave
			return &LintResult{Status: Warn}
		}
	}
	// If no bad usage was found, pass
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_sub_cert_eku_extra_values",
		Description:   "Subscriber Certificate: extKeyUsage values other than id-kp-documentSigning, id-kp-lifetimeSigning, and id-kp-emailProtection SHOULD NOT be present.",
		Citation:      "MRfCSC: Appendix B.3.F",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subExtKeyUsageLegalUsage{},
	})
}
