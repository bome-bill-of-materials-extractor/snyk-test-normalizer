import argparse
import sys
import json

def normalize_id(vuln):
    if vuln.get("CVE"):
        return vuln.get("CVE")[0]
    if vuln.get("CWE"):
        return vuln.get("CWE")[0]
    return ""

def convert(file, update_bome, output_file):
    if update_bome:
        bome = update_bome
        if not bome.get("vulnerabilities"):
            bome['vulnerabilities'] = []
    else:
        bome = {"vulnerabilities": []}
    with open(file) as f:
        snyk_test = json.load(f)
    for vuln in snyk_test.get("vulnerabilities", []):
        bome.get("vulnerabilities").append({
            "id": normalize_id(vuln),
            "rating": vuln.get("severity"),
            "url": "",
            "description": vuln.get("description"),
            "source": "SNYK",
            "context": ""
        })
    with open(output_file, 'w') as f:
        json.dump(bome, f)


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    convert(args.file, args.update_bome, args.output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="The location of the json to convert")
    parser.add_argument("--update-bome", help="The location of the bome, if you want to update it rather than start from scratch", default="", nargs='?')
    parser.add_argument("--output-file", help="The location of the file to save the output", default="output.json", nargs='?')
    args = parser.parse_args()
    main(args)