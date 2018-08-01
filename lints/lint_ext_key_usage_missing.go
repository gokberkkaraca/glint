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

type cscKeyUsageMissing struct{}

func (l *cscKeyUsageMissing) Initialize() error {
	return nil
}

func (l *cscKeyUsageMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsCodeSigningCert(c)
}

func (l *cscKeyUsageMissing) Execute(c *x509.Certificate) *LintResult {
	if util.IsExtInCert(c, util.KeyUsageOID) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_key_usage_missing",
		Description:   "This extension MUST be present.",
		Citation:      "MRfCSC: Appendix B.3.E",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &cscKeyUsageMissing{},
	})
}
