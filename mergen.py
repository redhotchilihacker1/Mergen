import subprocess
import ssl
import socket
import sys
import requests
import random
import urllib3
import argparse
import json
import dns.resolver
import os
import hashlib
import shutil
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style
from urllib.parse import urlparse
from instagramy import InstagramUser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#for later use
def print_centered(text):
    terminal_width = shutil.get_terminal_size().columns
    padding_width = (terminal_width - len(text)) // 2
    print(" " * padding_width + text)

def print_banner_with_border(text):
    terminal_width = shutil.get_terminal_size().columns
    text_length = len(text)
    #print("\n")
    print(Style.BRIGHT + "-" * (text_length + 4) + Style.RESET_ALL)  # Above Header
    print(Style.BRIGHT + f"| {text} |" + Style.RESET_ALL)  # Header
    print(Style.BRIGHT + "-" * (text_length + 4) + Style.RESET_ALL)  # Below Header


def print_banner(url):
    ascii_banner = """
                                            
███╗   ███╗███████╗██████╗  ██████╗ ███████╗███╗   ██╗
████╗ ████║██╔════╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║
██╔████╔██║█████╗  ██████╔╝██║  ███╗█████╗  ██╔██╗ ██║
██║╚██╔╝██║██╔══╝  ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║
██║ ╚═╝ ██║███████╗██║  ██║╚██████╔╝███████╗██║ ╚████║
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
                                                  
    """
    print(ascii_banner)

def print_url(url):
    print(f"{bcolors.BOLD}{Fore.BLUE}{url}{Style.RESET_ALL}\n")  # User-supplied URL

def check_ssl_versions(url):
    if url.startswith("http://"):
        print("HTTP protocol in use, skipping...")
        return

    if url.startswith("https://"):
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            url = url[8:]  # remove "https://"

            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    ssl_version = ssock.version()
                    print(f"{url} TLS in use. Version: {ssl_version}")

        except ssl.SSLError as e:
            if "sslv3 alert handshake failure" in str(e):
                print(f"{url} {Fore.RED}SSLv3 in use.{Style.RESET_ALL}")
            elif "sslv2 alert handshake failure" in str(e):
                print(f"{url} {Fore.RED}SSLv2 in use.{Style.RESET_ALL}")
            else:
                print(f"{url} SSL/TLS version unknown.")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Invalid URL.")


def check_sslv2_support(url):
    try:
        if url.startswith("http://"):
            return
        elif url.startswith("https://"):
            url = url[8:]
            
        result = subprocess.run(['openssl', 's_client', '-connect', f'{url}:443', '-ssl2'], capture_output=True, text=True, timeout=10)
        if "SSL-Session:" in result.stdout:
            print(f"{url} {Fore.RED}SSLv2 supported.{Style.RESET_ALL}")
        else:
            print(f"{url} {Fore.GREEN}SSLv2 doesn't supported.{Style.RESET_ALL}")
    except subprocess.TimeoutExpired:
        print("İşlem zaman aşımına uğradı.")
    except Exception as e:
        print(f"Hata: {e}")

def check_sslv3_support(url):
    try:
        if url.startswith("http://"):
            return
        elif url.startswith("https://"):
            url = url[8:]
            
        result = subprocess.run(['openssl', 's_client', '-connect', f'{url}:443', '-ssl3'], capture_output=True, text=True, timeout=10)
        if "SSL-Session:" in result.stdout:
            print(f"{url} {Fore.RED}SSLv3 supported.{Style.RESET_ALL}")
        else:
            print(f"{url} {Fore.GREEN}SSLv3 doesn't supported.{Style.RESET_ALL}")
    except subprocess.TimeoutExpired:
        print("The process has timed out.")
    except Exception as e:
        print(f"Error: {e}")


def check_security_headers(url):
    try:
        response = requests.get(url, verify=False)
        headers = response.headers

        security_headers = {
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
            "Content-Security-Policy": "Content-Security-Policy" in headers,
            "X-XSS-Protection": "X-XSS-Protection" in headers,
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
            "Referrer-Policy": "Referrer-Policy" in headers,
            "Feature-Policy": "Feature-Policy" in headers
        }

        return security_headers
    except Exception as e:
        print("Error:", e)

def check_debugging_enabled(url):
    try:
        headers = {'Command': 'stop-debug'}
        response = requests.request('DEBUG', url, headers=headers, verify=False)
        if response.status_code == 200 and 'OK' in response.text:
            print(f"{Fore.GREEN + Style.BRIGHT}HTTP DEBUG is enabled.{Style.RESET_ALL}")
        elif response.status_code == 405:
            print(f"{Fore.RED + Style.BRIGHT}HTTP DEBUG method is not enabled.{Style.RESET_ALL}")
        elif response.status_code == 501:
            print(f"{Fore.RED + Style.BRIGHT}Host doesn't support HTTP DEBUG method.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED + Style.BRIGHT}Unexpected status code: {response.status_code}.{Style.RESET_ALL}")
            
        # Check for TRACE method
        if ('allow' in response.headers and 'TRACE' in response.headers['allow']) or ('public' in response.headers and 'TRACE' in response.headers['public']):
            print(f"{Fore.GREEN + Style.BRIGHT}TRACE method is allowed.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED + Style.BRIGHT}TRACE method is not allowed.{Style.RESET_ALL}")

        # Check for TRACK method
        if ('allow' in response.headers and 'TRACK' in response.headers['allow']) or ('public' in response.headers and 'TRACK' in response.headers['public']):
            print(f"{Fore.GREEN + Style.BRIGHT}TRACK method is allowed.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED + Style.BRIGHT}TRACK method is not allowed.{Style.RESET_ALL}")
    
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED + Style.BRIGHT}Error: {e}{Style.RESET_ALL}")

def get_hash_type(value):
    # Hash types
    hash_types = {
        32: "MD5",
        40: "SHA1",
        60: "bcrypt",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512"
    }
    
    # Take the lenght of the hash
    value_length = len(value)
    
    # Determin the hash type by it's lenght
    if value_length in hash_types.keys():
        return hash_types[value_length]
    else:
        return "Unknown"

def print_cookie(cookie):
    print("Cookie Name:", cookie.name)
    print("Cookie Value:", cookie.value)
    print("Cookie Hash Type:", get_hash_type(cookie.value))
    
    if cookie.get_nonstandard_attr('httponly'):
        print("HTTPOnly:", Fore.GREEN + Style.BRIGHT + "True" + Style.RESET_ALL)
    else:
        print("HTTPOnly:", Fore.RED + Style.BRIGHT + "False" + Style.RESET_ALL)
    
    if cookie.get_nonstandard_attr('samesite') is None:
        print("SameSite:", Fore.RED + Style.BRIGHT + "None" + Style.RESET_ALL)
    else:
        print("SameSite:", Fore.GREEN + Style.BRIGHT + str(cookie.get_nonstandard_attr('samesite')) + Style.RESET_ALL)
    
    if cookie.secure:
        print("Secure:", Fore.GREEN + Style.BRIGHT + "True" + Style.RESET_ALL)
    else:
        print("Secure:", Fore.RED + Style.BRIGHT + "False" + Style.RESET_ALL)
        
    print("---------------------------------------")

def get_cookies_from_url(url):
    try:
        response = requests.get(url, verify=False)
        cookies = response.cookies

        if not cookies:
            print("Couldn't find any cookies to process.")
            return

        for cookie in cookies:
            print_cookie(cookie)

    except Exception as e:
        print("Error:", e)

def get_technologies(url):
    try:
        result = subprocess.run(['wad', '-u', url], capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print("Error: Couldn't retrieve technologies.")
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None

def check_social_media_links(url):
    social_media_links = {
        "facebook": "https://www.facebook.com/",
        "instagram": "https://www.instagram.com/",
        "linkedin": "https://www.linkedin.com/",
        "twitter": "https://twitter.com/",
        "github": "https://github.com/"
    }
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/87.0.4280.77 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.181 Mobile Safari/537.36"
    ]
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for social_media, link in social_media_links.items():
                social_media_link = soup.find('a', href=lambda href: href and social_media in href.lower())
                if social_media_link:
                    social_media_url = social_media_link['href']
                    print(f"Checking {social_media.capitalize()} link: {social_media_url}")
                    if social_media.lower() == "instagram":
                        check_instagram_link(social_media_url)
                    else:
                        check_social_media_link(social_media, social_media_url, user_agents)
                else:
                    print(f"No {social_media.capitalize()} link found.")
        else:
            print(f"Failed to fetch page: {url}")
            print("Unable to check social media links due to an error")
    except requests.RequestException:
        print("Failed to fetch page. Please check the provided URL.")
        print("Unable to check social media links due to an error")

def check_social_media_link(social_media, url, user_agents):
    try:
        user_agent = random.choice(user_agents)
        response = requests.head(url, allow_redirects=True, headers={"User-Agent": user_agent})
        if response.status_code == 200:
            if social_media.lower() == "facebook":
                if "sorry, this page isn't available" in response.text.lower():
                    print("Broken Facebook Link")
            elif social_media.lower() == "linkedin":
                if "this page doesn't exist" in response.text.lower():
                    print("Broken LinkedIn Link")
            elif social_media.lower() == "twitter":
                if "this account doesn't exist" in response.text.lower():
                    print("Broken Twitter Link")
            elif social_media.lower() == "github":
                if "there isn't a GitHub pages site here" in response.text.lower():
                    print("Broken Github Link")
        else:
            print(f"Unable to check {social_media.capitalize()} link due to an error")
    except requests.RequestException:
        print(f"Unable to check {social_media.capitalize()} link due to an error")

def check_instagram_link(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Gather the instagram username
            instagram_username = url.split('/')[-1]
            # Check if the username is in the source code
            if instagram_username in soup.text:
                print("Instagram account exists")
            else:
                print(f"{bcolors.FAIL}{bcolors.BOLD}Broken Instagram Link{bcolors.ENDC}")
        else:
            print("Failed to fetch page.")
    except requests.RequestException as e:
        print(f"Unable to check Instagram link due to an error: {e}")



def check_cors_vulnerability(url):
    # Reflected Origins Test
    reflected_origins_response = requests.get(url, headers={"Origin": "https://attackerdomain.com"}, verify=False)
    if "https://attackerdomain.com" in reflected_origins_response.headers.get("Access-Control-Allow-Origin", "") and \
            "true" in reflected_origins_response.headers.get("Access-Control-Allow-Credentials", "").lower():
        print("\033[1m\033[92mReflected Origins Test: Potential CORS \033[0m")
    else:
        print("\033[1m\033[91mReflected Origins Test: No Potential CORS\033[0m")

    # Trusted Subdomains Test
    attacker_domain = url.split("//")[1].split("/")[0]
    trusted_subdomains_response = requests.get(url, headers={"Origin": f"https://attacker.{attacker_domain}"}, verify=False)
    if trusted_subdomains_response.headers.get("Access-Control-Allow-Origin", ""):
        print("\033[1m\033[92mTrusted Subdomains Test: Potential CORS\033[0m")
    else:
        print("\033[1m\033[91mTrusted Subdomains Test: No Potential CORS\033[0m")

    # Null Origin Test
    null_origin_response = requests.get(url, headers={"Origin": "null"}, verify=False)
    if "null" in null_origin_response.headers.get("Access-Control-Allow-Origin", "") and \
            "true" in null_origin_response.headers.get("Access-Control-Allow-Credentials", "").lower():
        print("\033[1m\033[92mNull Origin Test: Potential CORS\033[0m")
    else:
        print("\033[1m\033[91mNull Origin Test: No Potential CORS\033[0m")

def scan_popular_ports(url):
    try:
        # Remove "http://" or "https://" from the URL if present
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
            
        open_ports = []

        popular_ports = [
        21, 22, 23, 25, 69, 80, 110, 111, 119, 135, 139, 143, 993, 161, 199,
        389, 636, 443, 554, 587, 631, 631, 993, 995, 995, 1025, 1030, 1433,
        1521, 2049, 2100, 3268, 3306, 3339, 3389, 4445, 4555, 465, 4700, 5357,
        5722, 5900, 5900, 8080, 9389
    ]

        for port in popular_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((url, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception as e:
                print(f"Error: {e}")

        for port in open_ports:
            print(f"Port {port} is open")

    except Exception as e:
        print(f"Error: {e}")

def check_spf(domain):
    try:
        domain = domain.split("//")[-1].split("/")[0]  # Take only domain name
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.strings
            for record in txt_record:
                if record.decode().startswith("v=spf"):
                    return True
        return False
    except dns.resolver.NoAnswer:
        return False

def check_dmarc(domain):
    try:
        domain = domain.split("//")[-1].split("/")[0]  # Take only domain name
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt_record = rdata.strings
            for record in txt_record:
                if record.decode().startswith("v=DMARC"):
                    return True
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
        
def clickjacking(url):
    response = requests.get(url)
    headers = response.headers
    if ('X-Frame-Options' in headers and 
        (headers['X-Frame-Options'] == 'DENY' or headers['X-Frame-Options'] == 'sameorigin')) or \
       ('Content-Security-Policy' in headers and 'frame-ancestors' in headers['Content-Security-Policy']):
        return False
    else:
        html_content = f"""
        <html>
            <head>
                <title>Clickjack test page</title>
            </head>
            <body>
                <iframe src="{url}" width="1000" height="1000"></iframe>
            </body>
        </html>
        """
        with open("clickjack_test.html", "w") as file:
            file.write(html_content)
        print("HTML file generated: clickjack_test.html")
        print("You can open the file by clicking the link below:")
        print(f"file://{os.getcwd()}/clickjack_test.html")
        return True

def get_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    urls = [url.strip() for url in urls]
    domains = [urlparse(url).netloc for url in urls]
    return domains
    

def main():
    try:
        parser = argparse.ArgumentParser(description="This script performs various security checks on a given website.")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-url", nargs="*", type=str, help="URL of the website to be analyzed")
        group.add_argument("-file", type=str, help="File containing URLs to be analyzed")
        parser.add_argument("-cookie", action="store_true", help="Enable checking of cookie values")
        parser.add_argument("-method", action="store_true", help="Check which HTTP Debugging methods are enabled")
        parser.add_argument("-headers", action="store_true", help="Enable checking of security headers")
        parser.add_argument("-ssl", action="store_true", help="Enable checking of SSL/TLS versions")
        parser.add_argument("-tech", action="store_true", help="Identify web technologies used")
        parser.add_argument("-social", action="store_true", help="Check social media links on the website")
        parser.add_argument("-cors", action="store_true", help="Check for CORS vulnerabilities on the website")
        parser.add_argument("-ports", action="store_true", help="Scan for popular ports")
        parser.add_argument("-spf", action="store_true", help="Perform SPF policy check")
        parser.add_argument("-dmarc", action="store_true", help="Perform DMARC policy check")
        parser.add_argument("-cjacking", action="store_true", help="Perform clickjacking vulnerability check")
        parser.add_argument("-all", action="store_true", help="Perform all checks")

        args = parser.parse_args()
            
        if args.all and (args.cookie or args.method or args.headers or args.ssl or args.tech or args.social or args.cors or args.ports or args.spf or args.dmarc or args.cjacking):
            parser.error("-all flag can only be used with -file and -url flags")


        urls = args.url or []  
        if args.file:
            with open(args.file, 'r') as file:
                file_contents = file.read().strip() 
            if file_contents:
                urls += file_contents.splitlines()  


        printed_banner = False
        for url in urls:
            if not printed_banner:  
                print_banner(url)  
                printed_banner = True
                
            print_banner_with_border(f"Checking {url}")

            ip_address = socket.gethostbyname(urlparse(url).hostname)
            hostname = urlparse(url).hostname

            start_time = datetime.now()

            print(f"IP Address: {ip_address}")
            print(f"Hostname: {hostname}")
            print(f"Scan Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

            if args.ssl or args.all:
                print_banner_with_border("SSL/TLS Versions")
                check_ssl_versions(url)
                check_sslv2_support(url)
                check_sslv3_support(url)
                print("\n")

            if args.cookie or args.all:
                print_banner_with_border("Cookie Check")
                get_cookies_from_url(url)
                print("\n")

            if args.headers or args.all:
                print_banner_with_border("Security Headers")
                result = check_security_headers(url)
                for header, present in result.items():
                    if present:
                        print(header + ":", Fore.GREEN + Style.BRIGHT + "Present" + Style.RESET_ALL)
                    else:
                        print(header + ":", Fore.RED + Style.BRIGHT + "Not Present" + Style.RESET_ALL)
                print("\n")

            if args.method or args.all:
                print_banner_with_border("HTTP Debugging Methods")
                debug_result = check_debugging_enabled(url)
                print("\n")

            if args.tech or args.all:
                print_banner_with_border("Web Technologies")
                technologies = get_technologies(url)
                if technologies:
                    print("Technologies used in the given website:")
                    for category, tech_list in technologies.items():
                        print(f"\n{category.capitalize()}:")
                        for tech_entry in tech_list:
                            app = tech_entry.get('app', 'Unknown Technology')
                            ver = tech_entry.get('ver', 'Unknown Version')
                            type_ = tech_entry.get('type', 'Unknown Type')
                            print(f"Application: {app}\nVersion: {ver}\nType: {type_}\n")
                    print("\n")
                else:
                    print("No technologies found.")


            if args.social or args.all:
                print_banner_with_border("Broken Link Hijack Check")
                check_social_media_links(url)
                print("\n")

            if args.cors or args.all:
                print_banner_with_border("CORS Misconfigurations")
                check_cors_vulnerability(url)
                print("\n")

            if args.ports or args.all:
                print_banner_with_border("Port Scan")
                scan_popular_ports(url)
                print("\n")

            if args.spf or args.all:
                print_banner_with_border("SPF Policy Check")
                spf_result = check_spf(url)
                if spf_result:
                    print("SPF record have been found")
                else:
                    print("SPF record have not been found")
                print("\n")

            if args.dmarc or args.all:
                print_banner_with_border("DMARC Policy Check")
                dmarc_result = check_dmarc(url)
                if dmarc_result:
                    print("DMARC record have been found")
                else:
                    print("DMARC record have not been found")
                print("\n")

            if args.cjacking or args.all:
                print_banner_with_border("Clickjacking Check")
                cjacking_result = clickjacking(url)
                if cjacking_result:
                    print(f"{Fore.GREEN + Style.BRIGHT}Possibble Clickjacking vulnerability.{Style.RESET_ALL}")
                else:
                    print("Clickjacking vulnerability not found.")
                print("\n")
                
            end_time = datetime.now()
            print(f"Scan End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            total_time = end_time - start_time
            total_seconds = round(total_time.total_seconds(), 1)
            print("Total Scan Time:", total_seconds, "seconds.\n\n\n")


    except KeyboardInterrupt:
        print(f"{bcolors.FAIL + bcolors.BOLD}The scan has been terminated by the user.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
