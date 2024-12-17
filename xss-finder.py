import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import os

# XSS Payloads (HTML, Attribute, JS)
BASE_PAYLOADS = [
    "</script><script>alert('xss')</script>",
    "<iframe><textarea></iframe><img src='' onerror='alert(\"xss\")'>",
    "<img/src/onerror=alert('xss')>",
    "Test123\"><img/src/onerror=alert('xss')>A",
    "<script>alert('xss')</script>"
]

# Reflected Parameter payload marker
REFLECTION_MARKER = "reflect_test_parameter"

def print_banner():
    """Print the banner for the tool."""
    banner = r""" ,  ,    _,    _,       __,       ___,      ,  ,        ,_          _,       ,_   
 \_/    (_,   (_,      '|_,      ' |        |\ |        | \,       /_,       |_)  
 / \     _)    _)       |         _|_,      |'\|       _|_/       '\_       '| \  
'   `   '     '         '        '          '  `      '              `       '  ` 
                                                                                  

    Automated XSS & Reflected Parameter Finder Tool
    Author: rootdr | Twitter: @R00TDR , Telegram: https://t.me/RootDr
    """
    print(colored(banner, "cyan"))

def fetch_url(url):
    """Fetch content of a URL."""
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except requests.RequestException:
        return None

def is_internal_url(url, target_domain):
    """Check if the URL is internal (belongs to the same domain)."""
    parsed_url = urlparse(url)
    return parsed_url.netloc.endswith(target_domain)

def crawl_domain(target, crawl_subdomains=False):
    """Crawl the domain and extract unique pages and their GET parameters."""
    print(colored("[*] Crawling the domain for pages and parameters...", "yellow"))
    crawled_urls = set()
    parameters = set()
    to_visit = {target}

    target_domain = urlparse(target).netloc

    # Create target folder for saving results
    target_folder = target_domain.replace(".", "_")
    os.makedirs(target_folder, exist_ok=True)

    try:
        while to_visit:
            url = to_visit.pop()
            if url in crawled_urls:
                continue

            crawled_urls.add(url)
            response = fetch_url(url)
            if not response:
                continue

            # Parse the page and extract links
            soup = BeautifulSoup(response, "html.parser")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])

                # Only crawl internal URLs, avoid subdomains unless -s is used
                if crawl_subdomains or is_internal_url(full_url, target_domain):
                    to_visit.add(full_url)

                # Extract GET parameters
                parsed = urlparse(full_url)
                query_params = parse_qs(parsed.query)
                for param in query_params.keys():
                    parameters.add((full_url.split("?")[0], param))  # (base_url, parameter)

    except KeyboardInterrupt:
        print(colored("[!] Crawling stopped by user.", "red"))

    return crawled_urls, parameters, target_folder

def test_xss(base_url, param, payloads):
    """Test XSS by injecting payloads into parameters."""
    for payload in payloads:
        try:
            params = {param: payload}
            response = requests.get(base_url, params=params, timeout=5)
            if payload in response.text:
                return f"{base_url}?{param}={payload}"
        except requests.RequestException:
            pass
    return None

def check_reflected_parameter(base_url, param):
    """Test if a parameter reflects its input by using a simple payload."""
    test_value = REFLECTION_MARKER
    query = {param: test_value}
    try:
        response = requests.get(base_url, params=query, timeout=5)
        if test_value in response.text:
            return f"{base_url}?{param}={test_value}"  # Found reflection
    except requests.exceptions.RequestException:
        pass  # Ignore request errors
    return None

def main():
    # Print banner
    print_banner()

    # Parse arguments
    parser = argparse.ArgumentParser(description="Automated XSS & Reflected Parameter Finder Tool")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Crawl subdomains as well")
    args = parser.parse_args()

    target = args.target
    crawl_subdomains = args.subdomains

    if not target.startswith("http://") and not target.startswith("https://"):
        print(colored("[!] Target URL must start with http:// or https://", "red"))
        return

    # Crawl the domain and extract parameters
    crawled_urls, parameters, target_folder = crawl_domain(target, crawl_subdomains)
    print(colored(f"[*] Crawled {len(crawled_urls)} unique pages.", "yellow"))
    print(colored(f"[*] Found {len(parameters)} unique parameters.", "yellow"))

    # Save crawled URLs to a text file
    target_domain_without_tld = target.split("//")[-1].split("/")[0].split(".")[0]
    crawled_urls_filename = f"crawled-{target_domain_without_tld}-crawled-urls.txt"
    with open(os.path.join(target_folder, crawled_urls_filename), "w", encoding="utf-8") as file:
        for url in crawled_urls:
            file.write(url + "\n")
    print(colored(f"[*] Saved crawled URLs to {crawled_urls_filename}", "cyan"))

    # Test for XSS vulnerabilities
    print(colored("[*] Testing for XSS vulnerabilities...", "yellow"))
    xss_results = []
    with tqdm(total=len(parameters), desc="Testing Parameters", unit="param") as progress_bar:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(test_xss, base_url, param, BASE_PAYLOADS)
                for base_url, param in parameters
            ]
            for future in as_completed(futures):
                progress_bar.update(1)
                result = future.result()
                if result:
                    xss_results.append(result)

    # Output results
    if xss_results:
        print(colored("\n[+] XSS Vulnerabilities Found:", "green"))
        for result in xss_results:
            print(colored(result, "green"))
        with open(os.path.join(target_folder, "xss_results.txt"), "w", encoding="utf-8") as result_file:
            for result in xss_results:
                result_file.write(result + "\n")
        print(colored("\n[+] Results saved to xss_results.txt", "cyan"))
    else:
        print(colored("\n[-] No XSS vulnerabilities found.", "red"))

if __name__ == "__main__":
    main()
