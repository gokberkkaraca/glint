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

/************************************************
RFC 5280: 4.2.2.1
An authorityInfoAccess extension may include multiple instances of
   the id-ad-caIssuers accessMethod.  The different instances may
   specify different methods for accessing the same information or may
   point to different information.  When the id-ad-caIssuers
   accessMethod is used, at least one instance SHOULD specify an
   accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.

************************************************/

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type aiaNoHTTPorLDAP struct{}

func (l *aiaNoHTTPorLDAP) Initialize() error {
	return nil
}

func (l *aiaNoHTTPorLDAP) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.AiaOID) && c.IssuingCertificateURL != nil
}

func (l *aiaNoHTTPorLDAP) Execute(c *x509.Certificate) *LintResult {
	for _, caIssuer := range c.IssuingCertificateURL {
		if caIssuer = strings.ToLower(caIssuer); strings.HasPrefix(caIssuer, "http://") || strings.HasPrefix(caIssuer, "ldap://") {
			return &LintResult{Status: Pass}
		}
	}
	return &LintResult{Status: Warn}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_ext_aia_access_location_missing",
		Description:   "When the id-ad-caIssuers accessMethod is used, at least one instance SHOULD specify an accessLocation that is an HTTP or LDAP URI",
		Citation:      "RFC 5280: 4.2.2.1",
		Source:        RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          &aiaNoHTTPorLDAP{},
	})
}
