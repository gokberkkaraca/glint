import json
import glob

lint_dictionary = {}

for lint in glob.glob('lints/lint*'):
    lint = lint[11:][:-3]  # Parse file name to extract lint name
    if "test" in lint:
        continue
    else:
        lint_dictionary[lint] = {"Pass": 0, "Notice": 0, "Warning": 0, "Error": 0}

for file in glob.glob('pem_certificates/certs_newer_2017/*.json'):
    file_content = open(file).read()
    json_file = json.loads(file_content)
    for key in list(json_file):
        json_file[key[2:]] = json_file[key]
        del json_file[key]

    for lint in lint_dictionary:
        if json_file[lint] == "pass":
            lint_dictionary[lint]["pass"] += 1
        if json_file[lint] == "notice":
            lint_dictionary[lint]["notice"] += 1
        if json_file[lint] == "warn":
            lint_dictionary[lint]["warn"] += 1
        if json_file[lint] == "error":
            lint_dictionary[lint]["error"] += 1

print("Hello, World!")
