import sqlite3


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

ca_list = [row[0] for row in db.execute("SELECT DISTINCT certificate_issuer FROM certificates;")]
print("CA list retrieved from database")

years = list(range(2015, 2019))
months = list(range(1, 13))

filter_results = True

for ca in ca_list:
    print("\nAnalysis results for: ", ca)
    for lint in lints_to_be_analyzed_list:
        certificates_issued_by_ca = [row for row in db.execute("SELECT certificate_id, lint_name, certificate_date, result FROM certificates NATURAL JOIN results WHERE certificate_issuer=? AND lint_name LIKE '%"+ lint + "%'", (ca,))]
        result_list = list(map(lambda item: item[3], certificates_issued_by_ca))
        total = len(result_list)
        _error = len(list(filter(lambda item: item=='error', result_list)))
        _pass = len(list(filter(lambda item: item=='pass', result_list)))
        _info = len(list(filter(lambda item: item=='info', result_list)))
        _warn = len(list(filter(lambda item: item=='warn', result_list)))
        _NA = len(list(filter(lambda item: item=='NA', result_list)))
        _NE = len(list(filter(lambda item: item=='NE', result_list)))
        success_rate = (_pass + _NA + _NE)/total
        check = False
        if success_rate != 1.0:
            check = True

        if filter_results:
            if check:
                print("{}, Total: {}, Error: {}, Pass: {}, Info: {}, Warn: {}, NA: {}, NE: {}, Success: {}"
                      .format(lint, total, _error, _pass, _info, _warn, _NA, _NE, success_rate))
        else:
            print("{}, Total: {}, Error: {}, Pass: {}, Info: {}, Warn: {}, NA: {}, NE: {}, Success: {}"
                  .format(lint, total, _error, _pass, _info, _warn, _NA, _NE, success_rate))



