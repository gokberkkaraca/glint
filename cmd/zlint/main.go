/*
 * ZLint Copyright 2017 Regents of the University of Michigan
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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/gokberkkaraca/glint"
	"github.com/gokberkkaraca/glint/lints"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var ( // flags
	listLintsJSON   bool
	listLintsSchema bool
	prettyprint     bool
	format          string
	db *sql.DB
	err 			error
)

func init() {
	flag.BoolVar(&listLintsJSON, "list-lints-json", false, "Print supported lints in JSON format, one per line")
	flag.BoolVar(&listLintsSchema, "list-lints-schema", false, "Print supported lints as a ZSchema")
	flag.StringVar(&format, "format", "der", "One of {pem, der, base64}")
	flag.BoolVar(&prettyprint, "pretty", true, "Pretty-print output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] file...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetLevel(log.InfoLevel)
}

func main() {

	if listLintsJSON {
		zlint.EncodeLintDescriptionsToJSON(os.Stdout)
		return
	}

	if listLintsSchema {
		names := make([]string, 0, len(lints.Lints))
		for lintName := range lints.Lints {
			names = append(names, lintName)
		}
		sort.Strings(names)
		fmt.Printf("Lints = SubRecord({\n")
		for _, lintName := range names {
			fmt.Printf("    \"%s\":LintBool(),\n", lintName)
		}
		fmt.Printf("})\n")
		return
	}


	db, err = sql.Open("sqlite3", "./lint_results.db")
	checkDatabaseError(err)

	insertLints()

	var inform = strings.ToLower(format)
	if flag.NArg() < 1 || flag.Arg(0) == "-" {
		lint(os.Stdin, inform)
	} else {
		pathToCertificates := flag.Arg(0)
		fmt.Println("Starting to read directory.")
		files, err := ioutil.ReadDir(pathToCertificates)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("All files are read, starting certificate analysis.")

		for _, filePath := range files {
			var inputFile *os.File
			var err error
			inputFile, err = os.Open(pathToCertificates + filePath.Name())
			if err != nil {
				log.Fatalf("unable to open file %s: %s", filePath, err)
			}
			var cert_fmt = inform
			switch {
			case strings.HasSuffix(filePath.Name(), ".der"):
				cert_fmt = "der"
			case strings.HasSuffix(filePath.Name(), ".pem"):
				cert_fmt = "pem"
			}
			lint(inputFile, cert_fmt)
			inputFile.Close()
		}
	}
}

func lint(inputFile *os.File, inform string) {
	splitPath := strings.Split(inputFile.Name(), "/")
	certID := splitPath[len(splitPath) - 1]

	fmt.Println("Analysing certificate: ", certID)
	fileBytes, err := ioutil.ReadAll(inputFile)
	if err != nil {
		log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
	}

	var asn1Data []byte
	switch inform {
	case "pem":
		p, _ := pem.Decode(fileBytes)
		if p == nil || p.Type != "CERTIFICATE" {
			log.Fatal("unable to parse PEM")
		}
		asn1Data = p.Bytes
	case "der":
		asn1Data = fileBytes
	case "base64":
		asn1Data, err = base64.StdEncoding.DecodeString(string(fileBytes))
		if err != nil {
			log.Fatalf("unable to parse base64: %s", err)
		}
	default:
		log.Fatalf("unknown input format %s", format)
	}

	c, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		log.Fatalf("unable to parse certificate: %s", err)
	}

	insertCertificate(certID, c)

	resultSet := zlint.LintCertificate(c)
	insertResults(certID, resultSet)
}

func printResultsToConsole(zlintResult *zlint.ResultSet) {
	jsonBytes, err := json.Marshal(zlintResult.Results)
	if err != nil {
		log.Fatalf("unable to encode lints JSON: %s", err)
	}
	if prettyprint {
		var out bytes.Buffer
		if err := json.Indent(&out, jsonBytes, "", " "); err != nil {
			log.Fatalf("can't format output: %s", err)
		}
		os.Stdout.Write(out.Bytes())
	} else {
		os.Stdout.Write(jsonBytes)
	}
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Sync()
}

func insertCertificate(certID string, certificate *x509.Certificate) {

	var organizationName string
	if len(certificate.Subject.Organization) != 0 {
		organizationName = certificate.Subject.Organization[0]
	}
	stmt, err := db.Prepare("INSERT INTO certificates(certificate_id, certificate_issuer, certificate_date) VALUES(?, ?, ?)")
	checkDatabaseError(err)
	_, err = stmt.Exec(certID, organizationName, certificate.NotBefore)
	checkDatabaseError(err)
}

func insertLints() {

	var sourceMap = map[lints.LintSource]string {
		0: "UnknownLintSource",
		1: "CABFBaselineRequirements",
		2: "MinimumRequirementsForCodeSigningCertificates",
		3: "RFC5280",
		4: "RFC5891",
		5: "ZLint",
		6: "AWSLabs",
	}

	for _, lint := range lints.Lints {
		stmt, err := db.Prepare("INSERT OR IGNORE INTO lints(lint_name, lint_source, lint_effective_date) VALUES(?,?,?)")
		checkDatabaseError(err)
		_, err = stmt.Exec(lint.Name, sourceMap[lint.Source], lint.EffectiveDate)
		checkDatabaseError(err)
	}
}

func insertResults(certID string, resultSet *zlint.ResultSet) {

	for lint, result := range resultSet.Results {
		stmt, err := db.Prepare("INSERT INTO results(certificate_id, lint_name, result) VALUES(?,?,?)")
		checkDatabaseError(err)
		_, err = stmt.Exec(certID, lint, result.Status.String())
		checkDatabaseError(err)
	}
}

func checkDatabaseError(err error) {
	if err != nil {
		fmt.Println("Operation failed")
		panic(err)
	}
}