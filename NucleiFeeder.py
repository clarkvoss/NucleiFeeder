import base64
import xml.etree.ElementTree as ET
import subprocess
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def process_burp_xml(xml_file, nuclei_templates):
    """
    Parses a Burp Suite XML file, extracts unique GET requests, and sends them to Nuclei.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    processed_urls = set()  # Track unique URLs

    for item in root.findall("item"):
        try:
            # Extract request details
            request_base64 = item.find("request").text
            host = item.find("host").text
            protocol = item.find("protocol").text
            port = item.find("port").text

            # Decode Base64 request
            request_raw = base64.b64decode(request_base64).decode("utf-8")
            method, url, _, _ = parse_http_request(request_raw, host, protocol, port)

            # Skip non-GET requests and duplicates
            if method != "GET" or url in processed_urls:
                continue
            processed_urls.add(url)

            # Feed the URL to Nuclei
            feed_to_nuclei(url, nuclei_templates)

        except Exception as e:
            print(f"Error processing item: {e}")

def parse_http_request(request_raw, host, protocol, port):
    """
    Parses a raw HTTP request into method, URL, headers, and body.
    """
    lines = request_raw.split("\n")
    method, path, _ = lines[0].split()

    # Construct full URL
    url = f"{protocol}://{host}:{port}{path}"

    return method, url, None, None

def feed_to_nuclei(url, templates):
    """
    Feeds the extracted URL to Nuclei for testing directly as a parameter.
    """
    # Construct Nuclei command
    nuclei_cmd = f"nuclei -u {url} -t {templates}  -ni -rl 30 -bs 10 -c 10"

    try:
        print(f"Running Nuclei: {nuclei_cmd}")
        subprocess.run(nuclei_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running Nuclei: {e}")

# Example usage
xml_file = "burp_output.xml"  # Path to Burp XML file
nuclei_templates = "nuclei-templates"  # Path to Nuclei templates
process_burp_xml(xml_file, nuclei_templates)
