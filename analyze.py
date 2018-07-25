import json
import glob

lint_dictionary = {}

# Create a lint dictionary from files in ./lints/ directory
for lint in glob.glob('lints/lint*'):
    lint = lint[11:][:-3]  # Parse file name to extract lint name
    if "test" in lint:  # Skip the file if it is a test file
        continue
    else:  # Create a dictionary that includes all possible results
        lint_dictionary[lint] = {
            "pass": 0,
            "notice": 0,
            "warn": 0,
            "error": 0,
            "NA": 0,
            "NE": 0,
            "certificates_causing_errors": []
        }

# Parse result of each certificate to update lint dictionary
for file in glob.glob('pem_certificates/certs_newer_2017/*.json'):
    file_content = open(file).read()
    if file_content == "":
        continue
    json_file = json.loads(file_content)
    for key in list(json_file):  # Modify lint message ignore first 3 characters
        json_file[key[2:]] = json_file[key]
        del json_file[key]

    for lint in lint_dictionary:  # Update the result of each lint with the results of current file
        if json_file[lint]['result'] == "pass":
            lint_dictionary[lint]["pass"] += 1
        elif json_file[lint]['result'] == "info":
            lint_dictionary[lint]["notice"] += 1
        elif json_file[lint]['result'] == "warn":
            lint_dictionary[lint]["warn"] += 1
        elif json_file[lint]['result'] == "error":
            lint_dictionary[lint]["error"] += 1
            lint_dictionary[lint]["certificates_causing_errors"].append(file.split("/")[2].split(".")[0])
        elif json_file[lint]['result'] == "NA":
            lint_dictionary[lint]["NA"] += 1
        elif json_file[lint]['result'] == "NE":
            lint_dictionary[lint]["NE"] += 1

# Find highest info
highest_pass_lint = list(lint_dictionary.keys())[0]
highest_info_lint = list(lint_dictionary.keys())[0]
highest_warn_lint = list(lint_dictionary.keys())[0]
highest_error_lint = list(lint_dictionary.keys())[0]

for lint in lint_dictionary:
    if lint_dictionary[lint]["pass"] > lint_dictionary[highest_pass_lint]["pass"]:
        highest_pass_lint = lint
    if lint_dictionary[lint]["warn"] > lint_dictionary[highest_warn_lint]["warn"]:
        highest_warn_lint = lint
    if lint_dictionary[lint]["notice"] > lint_dictionary[highest_info_lint]["notice"]:
        highest_info_lint = lint
    if lint_dictionary[lint]["error"] > lint_dictionary[highest_error_lint]["error"]:
        highest_error_lint = lint

# Print results to console and a file
result = json.dumps(lint_dictionary, indent=4) + "\n"
with open("certs_newer_2017.txt", "w") as file:
    file.write(result)
print(result)

print("Highest pass lint: {}, {}".format(highest_pass_lint, lint_dictionary[highest_pass_lint]["pass"]))
print("Highest info lint: {}, {}".format(highest_info_lint, lint_dictionary[highest_info_lint]["notice"]))
print("Highest warn lint: {}, {}".format(highest_warn_lint, lint_dictionary[highest_warn_lint]["warn"]))
print("Highest error lint: {}, {}".format(highest_error_lint, lint_dictionary[highest_error_lint]["error"]))
