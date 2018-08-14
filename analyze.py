import sqlite3
import json

db = sqlite3.connect('lint_results.db')
print("Connected to database.")

lints_to_be_analyzed_list = [
    "subject_common_name_missing",
    "subject_domain_component_included",
    "subject_organization_name_missing",
    "sub_cert_locality_name_must_appear",
    "sub_cert_province_must_appear",
    "sub_cert_country_name_must_appear",
    "sub_cert_eku_extra_values",
    "csc_cert_policy_missing",
    "csc_certificate_policy_identifier_missing",
    "csc_certificate_policy_marked_critical",
    "sub_cert_eku_prohibited_usage",
    "sub_cert_eku_cs_missing",
    "ext_key_usage_missing",
    "sub_cert_key_usage_digital_signature_bit_not_set",
    "postal_code_included_in_other_fields",
]
print("Registered the lints to be analyzed list")

ca_list = [row[0] for row in db.execute(
    "SELECT DISTINCT certificate_issuer FROM certificates where certificate_date > '2016';")]
print("CA list retrieved from database")

dates = ["2016-01", "2016-02", "2016-03", "2016-04", "2016-05", "2016-06",
         "2016-07", "2016-08", "2016-09", "2016-10", "2016-11", "2016-12",
         "2017-01", "2017-02", "2017-03", "2017-04", "2017-05", "2017-06"]

all_results = {}
for ca in ca_list:
    all_results.update({ca: {}})
    for lint in lints_to_be_analyzed_list:
        all_results[ca].update({lint: {}})


for date in dates:
    print("Collecting data for: ", date)
    for ca in ca_list:
        for lint in lints_to_be_analyzed_list:
            certificates_issued_by_ca = [row for row in db.execute(
                "SELECT certificate_id, lint_name, certificate_date, result FROM certificates NATURAL JOIN results "
                "WHERE certificate_date > ? AND certificate_issuer=? AND lint_name LIKE '%" + lint + "%'", (date, ca,))]
            result_list = list(map(lambda item: item[3], certificates_issued_by_ca))
            total = len(result_list)
            _error = len(list(filter(lambda item: item == 'error', result_list)))
            _pass = len(list(filter(lambda item: item == 'pass', result_list)))
            _info = len(list(filter(lambda item: item == 'info', result_list)))
            _warn = len(list(filter(lambda item: item == 'warn', result_list)))
            _NA = len(list(filter(lambda item: item == 'NA', result_list)))
            _NE = len(list(filter(lambda item: item == 'NE', result_list)))

            if total != 0:
                success_rate = (_pass + _NA + _NE)/total
                all_results[ca][lint].update({date: success_rate})
            else:
                success_rate = 1.0

with open("success_rates_each_month.json", "w") as file:
    json.dump(all_results, file, indent=4)
