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

/**********************************************************
RFC 5280: 4.2.1.5.  Policy Mappings
This extension MAY be supported by CAs and/or applications.
   Conforming CAs SHOULD mark this extension as critical.
**********************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type policyMapCritical struct{}

func (l *policyMapCritical) Initialize() error {
	return nil
}

func (l *policyMapCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.PolicyMapOID)
}

func (l *policyMapCritical) Execute(c *x509.Certificate) *LintResult {
	polMap := util.GetExtFromCert(c, util.PolicyMapOID)
	if polMap.Critical {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Warn}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_ext_policy_map_not_critical",
		Description:   "Policy mappings should be marked as critical",
		Citation:      "RFC 5280: 4.2.1.5",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &policyMapCritical{},
	})
}
