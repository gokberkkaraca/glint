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
"BRs: 6.1.6"
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 2^16+1 and 2^256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800-89].
*******************************************************************************************************/

import (
	"crypto/rsa"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint/util"
)

type rsaParsedTestsExpInRange struct {
	upperBound *big.Int
}

func (l *rsaParsedTestsExpInRange) Initialize() error {
	l.upperBound = &big.Int{}
	l.upperBound.Exp(big.NewInt(2), big.NewInt(256), nil)
	return nil
}

func (l *rsaParsedTestsExpInRange) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaParsedTestsExpInRange) Execute(c *x509.Certificate) *LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	exponent := key.E
	const lowerBound = 65536 // 2^16 + 1
	if exponent > lowerBound && l.upperBound.Cmp(big.NewInt(int64(exponent))) == 1 {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: Warn}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_rsa_public_exponent_not_in_range",
		Description:   "RSA: Public exponent SHOULD be in the range between 2^16 + 1 and 2^256 - 1",
		Citation:      "BRs: 6.1.6",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABV113Date,
		Lint:          &rsaParsedTestsExpInRange{},
	})
}
