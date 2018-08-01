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

/*If the Certificate asserts the policy identifier of 2.23.140.1.2.2, then it MUST also include organizationName, localityName (to the extent such field is required under Section 7.1.4.2.2), stateOrProvinceName (to the extent such field is required under Section 7.1.4.2.2), and countryName in the Subject field.*/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type CertPolicyRequiresOrg struct{}

func (l *CertPolicyRequiresOrg) Initialize() error {
	return nil
}

func (l *CertPolicyRequiresOrg) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BROrganizationValidatedOID) && !util.IsCACert(cert)
}

func (l *CertPolicyRequiresOrg) Execute(cert *x509.Certificate) *LintResult {
	var out LintResult
	if util.TypeInName(&cert.Subject, util.OrganizationNameOID) {
		out.Status = Pass
	} else {
		out.Status = Error
	}
	return &out
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_cab_ov_requires_org",
		Description:   "If certificate policy 2.23.140.1.2.2 is included, organizationName MUST be included in subject",
		Citation:      "BRs: 7.1.6.1",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &CertPolicyRequiresOrg{},
	})
}
