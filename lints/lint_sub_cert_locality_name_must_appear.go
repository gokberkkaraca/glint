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
	"github.com/zmap/zlint/util"
)

type subCertLocalityNameMustAppear struct{}

func (l *subCertLocalityNameMustAppear) Initialize() error {
	return nil
}

func (l *subCertLocalityNameMustAppear) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertLocalityNameMustAppear) Execute(c *x509.Certificate) *LintResult {
	if !util.TypeInName(&c.Subject, util.StateOrProvinceNameOID) && !util.TypeInName(&c.Subject, util.LocalityNameOID) {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_locality_name_must_appear",
		Description:   "Subscriber Certificate: subject:localityName MUST appear if subject:stateOrProvinceName field is absent",
		Citation:      "MRfCSC: 9.2.4.c",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertLocalityNameMustAppear{},
	})
}
