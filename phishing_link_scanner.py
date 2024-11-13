import re
import requests
from urllib.parse import urlparse

def is_suspicious_url(url):
    # Checking if the URL is IP-based
    ip_pattern = re.compile(r'http[s]?://(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.match(url):
        return True
    
    # Common keywords found in phishing URLs
    suspicious_keywords = ['login', 'verify', 'secure', 'account']
    
    # Breaking down the URL into parts (domain, path, etc.)
    parsed_url = urlparse(url)
    
    # Checking for keywords in the domain or path
    for keyword in suspicious_keywords:
        if keyword in parsed_url.netloc or keyword in parsed_url.path:
            return True  

    # Checking if URL is unusually long
    if len(url) > 75: 
        return True

    return False 

# VirusTotal API key
API_KEY = "95a364d9897702f78d23b1f2c429fe4f264a136d07312f191e90d8cbfb021f8e"  

def submit_url_to_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        return analysis_id
    else:
        print(f"Error: VirusTotal API submission failed with status code {response.status_code}")
        return None

def get_url_analysis_from_virustotal(analysis_id, api_key):
    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: VirusTotal API request failed with status code {response.status_code}")
        return None

def phishing_link_scanner(api_key=None):
    user_input = input("Enter URLs separated by commas: ")
    urls = [url.strip() for url in user_input.split(",")]

    for url in urls:
        if is_suspicious_url(url):
            print(f"Warning: Suspicious URL detected - {url}")
        elif api_key:
            analysis_id = submit_url_to_virustotal(url, api_key)
            if analysis_id:
                result = get_url_analysis_from_virustotal(analysis_id, api_key)
                if result and 'data' in result and 'attributes' in result['data']:
                    if result['data']['attributes']['stats']['malicious'] > 0:
                        print(f"Phishing detected by VirusTotal - {url}")
                    else:
                        print(f"URL appears safe - {url}")
                else:
                    print(f"Error processing URL with VirusTotal - {url}")
            else:
                print(f"Error: Could not submit URL for analysis - {url}")
        else:
            print(f"URL appears safe - {url}")

if __name__ == "__main__":
    phishing_link_scanner(api_key=API_KEY)
