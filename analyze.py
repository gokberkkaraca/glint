import json
import glob

lint_dictionary = {}

# Create a lint dictionary from files in ./lints/ directory
for lint in glob.glob('lints/lint*'):
    lint = lint[11:][:-3]  # Parse file name to extract lint name
    if "test" in lint:  # Skip the file if it is a test file
        continue
    else:  # Create a dictionary that includes all possible results
        lint_dictionary[lint] = {"pass": 0, "notice": 0, "warn": 0, "error": 0, "NA": 0, "NE": 0}

# Parse result of each certificate to update lint dictionary
for file in glob.glob('pem_certificates/certs_newer_2017/*.json'):
    file_content = open(file).read()
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
        elif json_file[lint]['result'] == "NA":
            lint_dictionary[lint]["NA"] += 1
        elif json_file[lint]['result'] == "NE":
            lint_dictionary[lint]["NE"] += 1

# Print results to console and a file
result = json.dumps(lint_dictionary, indent=4)
with open("result.txt", "w") as file:
    file.write(result)
print(result)
