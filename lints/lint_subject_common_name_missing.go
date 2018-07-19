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

/***************************************************************
MRfCSC: 9.2.2
Required/Optional: Required
***************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type commonNames struct{}

func (l *commonNames) Initialize() error {
	return nil
}

func (l *commonNames) CheckApplies(c *x509.Certificate) bool {
	return !util.IsCACert(c)
}

func (l *commonNames) Execute(c *x509.Certificate) *LintResult {
	if c.Subject.CommonName != "" {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_common_name_missing",
		Description:   "Subscriber Certificate: commonName is required.",
		Citation:      "MRfCSC: 9.2.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &commonNames{},
	})
}
