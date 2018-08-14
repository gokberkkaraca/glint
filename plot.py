import json
import matplotlib.pylab as pylab
import matplotlib.pyplot as plt


lint_coloring_scheme = {
    "subject_common_name_missing": 'b',
    "subject_domain_component_included": 'g',
    "subject_organization_name_missing": 'r',
    "sub_cert_locality_name_must_appear": 'c',
    "sub_cert_province_must_appear": 'm',
    "sub_cert_country_name_must_appear": 'y',
    "sub_cert_eku_extra_values": 'k',
    "csc_cert_policy_missing": 'mediumpurple',
    "csc_certificate_policy_identifier_missing": 'lightgreen',
    "csc_certificate_policy_marked_critical": 'steelblue',
    "sub_cert_eku_prohibited_usage": 'darksalmon',
    "sub_cert_eku_cs_missing": 'darkkhaki',
    "ext_key_usage_missing": 'cornflowerblue',
    "sub_cert_key_usage_digital_signature_bit_not_set": 'darkgoldenrod',
    "postal_code_included_in_other_fields": 'chartreuse'
}


json_string = open("success_rates_each_month.json").read()
all_results = json.loads(json_string)

for ca in all_results:
    plt.figure(figsize=(19.2, 10.8), dpi=100)
    for lint in all_results[ca]:
        plt.title(ca)
        plt.ylabel("success rate")
        plt.xlabel("dates")
        plt.plot(*zip(*sorted(all_results[ca][lint].items())), color=lint_coloring_scheme[lint], label=lint)
    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
    pylab.savefig("./plots/" + ca + ".png", bbox_inches="tight")
