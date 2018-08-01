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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type digitalSignatureBitNotSet struct{}

func (l *digitalSignatureBitNotSet) Initialize() error {
	return nil
}

func (l *digitalSignatureBitNotSet) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.KeyUsageOID) && !util.IsCACert(c) && util.IsCodeSigningCert(c)
}

func (l *digitalSignatureBitNotSet) Execute(c *x509.Certificate) *LintResult {
	// Add actual lint here
	if (c.KeyUsage & x509.KeyUsageDigitalSignature) != x509.KeyUsageDigitalSignature {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_key_usage_digital_signature_bit_not_set",
		Description:   "The bit positions for digitalSignature MUST be set.",
		Citation:      "MRfCSC: Appendix B.3.E",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &digitalSignatureBitNotSet{},
	})
}
