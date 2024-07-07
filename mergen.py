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
import base64
import dns.resolver
import cloudscraper
import time
from html import escape
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style
from urllib.parse import urlparse
from instagramy import InstagramUser
from requests.exceptions import SSLError
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def print_centered(text):
    terminal_width = shutil.get_terminal_size().columns
    padding_width = (terminal_width - len(text)) // 2
    print(" " * padding_width + text)

def print_banner_with_border(text):
    terminal_width = shutil.get_terminal_size().columns
    text_length = len(text)
    print(Style.BRIGHT + "-" * (text_length + 4) + Style.RESET_ALL)
    print(Style.BRIGHT + f"| {text} |" + Style.RESET_ALL)
    print(Style.BRIGHT + "-" * (text_length + 4) + Style.RESET_ALL)

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
    print(f"{bcolors.BOLD}{Fore.BLUE}{url}{Style.RESET_ALL}\n")

def check_ssl_versions(url, html_report):
    if url.startswith("http://"):
        print("HTTP protocol in use, skipping...")
        html_report.append("<p>HTTP protocol in use, skipping...</p>")
        return

    if url.startswith("https://"):
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            url_hostname = urlparse(url).hostname

            with socket.create_connection((url_hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url_hostname) as ssock:
                    ssl_version = ssock.version()
                    print(f"{url} TLS in use. Version: {ssl_version}")
                    html_report.append(f"<p>{url} TLS in use. Version: {ssl_version}</p>")

        except ssl.SSLError as e:
            if "sslv3 alert handshake failure" in str(e):
                print(f"{url} {Fore.RED}SSLv3 in use.{Style.RESET_ALL}")
                html_report.append(f"<p>{url} <span style='color:red;'>SSLv3 in use.</span></p>")
            elif "sslv2 alert handshake failure" in str(e):
                print(f"{url} {Fore.RED}SSLv2 in use.{Style.RESET_ALL}")
                html_report.append(f"<p>{url} <span style='color:red;'>SSLv2 in use.</span></p>")
            else:
                print(f"{url} SSL/TLS version unknown.")
                html_report.append(f"<p>{url} SSL/TLS version unknown.</p>")
        except Exception as e:
            print(f"Error: {e}")
            html_report.append(f"<p>Error: {e}</p>")
    else:
        print("Invalid URL.")
        html_report.append("<p>Invalid URL.</p>")

def check_sslv2_support(url, html_report):
    try:
        if url.startswith("http://"):
            return
        elif url.startswith("https://"):
            url_hostname = urlparse(url).hostname
            
        result = subprocess.run(['openssl', 's_client', '-connect', f'{url_hostname}:443', '-ssl2'], capture_output=True, text=True, timeout=10)
        if "SSL-Session:" in result.stdout:
            print(f"{url} {Fore.RED}SSLv2 supported.{Style.RESET_ALL}")
            html_report.append(f"<p>{url} <span style='color:red;'>SSLv2 supported.</span></p>")
        else:
            print(f"{url} {Fore.GREEN}SSLv2 doesn't supported.{Style.RESET_ALL}")
            html_report.append(f"<p>{url} <span style='color:green;'>SSLv2 doesn't supported.</span></p>")
    except subprocess.TimeoutExpired:
        print("The process has timed out.")
        html_report.append("<p>The process has timed out.</p>")
    except Exception as e:
        print(f"Error: {e}")
        html_report.append(f"<p>Error: {e}</p>")

def check_sslv3_support(url, html_report):
    try:
        if url.startswith("http://"):
            return
        elif url.startswith("https://"):
            url_hostname = urlparse(url).hostname
            
        result = subprocess.run(['openssl', 's_client', '-connect', f'{url_hostname}:443', '-ssl3'], capture_output=True, text=True, timeout=10)
        if "SSL-Session:" in result.stdout:
            print(f"{url} {Fore.RED}SSLv3 supported.{Style.RESET_ALL}")
            html_report.append(f"<p>{url} <span style='color:red;'>SSLv3 supported.</span></p>")
        else:
            print(f"{url} {Fore.GREEN}SSLv3 doesn't supported.{Style.RESET_ALL}")
            html_report.append(f"<p>{url} <span style='color:green;'>SSLv3 doesn't supported.</span></p>")
    except subprocess.TimeoutExpired:
        print("The process has timed out.")
        html_report.append("<p>The process has timed out.</p>")
    except Exception as e:
        print(f"Error: {e}")
        html_report.append(f"<p>Error: {e}</p>")

def check_security_headers(url, html_report):
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

        for header, present in security_headers.items():
            if present:
                print(header + ":", Fore.GREEN + Style.BRIGHT + "Present" + Style.RESET_ALL)
                html_report.append(f"<p>{header}: <span style='color:green;'>Present</span></p>")
            else:
                print(header + ":", Fore.RED + Style.BRIGHT + "Not Present" + Style.RESET_ALL)
                html_report.append(f"<p>{header}: <span style='color:red;'>Not Present</span></p>")

        return security_headers
    except Exception as e:
        print("Error:", e)
        html_report.append(f"<p>Error: {e}</p>")

def check_debugging_enabled(url, html_report):
    try:
        headers = {'Command': 'stop-debug'}
        response = requests.request('DEBUG', url, headers=headers, verify=False)
        if response.status_code == 200 and 'OK' in response.text:
            print(f"{Fore.RED + Style.BRIGHT}HTTP DEBUG is enabled.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:red;'>HTTP DEBUG is enabled.</span></p>")
        elif response.status_code == 405:
            print(f"{Fore.GREEN + Style.BRIGHT}HTTP DEBUG method is not enabled.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:green;'>HTTP DEBUG method is not enabled.</span></p>")
        elif response.status_code == 501:
            print(f"{Fore.GREEN + Style.BRIGHT}Host doesn't support HTTP DEBUG method.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:green;'>Host doesn't support HTTP DEBUG method.</span></p>")
        else:
            print(f"{Fore.RED + Style.BRIGHT}Unexpected status code: {response.status_code}.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:red;'>Unexpected status code: {response.status_code}.</span></p>")
            
        if ('allow' in response.headers and 'TRACE' in response.headers['allow']) or ('public' in response.headers and 'TRACE' in response.headers['public']):
            print(f"{Fore.RED + Style.BRIGHT}TRACE method is allowed.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:green;'>TRACE method is allowed.</span></p>")
        else:
            print(f"{Fore.GREEN + Style.BRIGHT}TRACE method is not allowed.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:green;'>TRACE method is not allowed.</span></p>")

        if ('allow' in response.headers and 'TRACK' in response.headers['allow']) or ('public' in response.headers and 'TRACK' in response.headers['public']):
            print(f"{Fore.RED + Style.BRIGHT}TRACK method is allowed.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:red;'>TRACK method is allowed.</span></p>")
        else:
            print(f"{Fore.GREEN + Style.BRIGHT}TRACK method is not allowed.{Style.RESET_ALL}")
            html_report.append(f"<p><span style='color:green;'>TRACK method is not allowed.</span></p>")
    
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED + Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
        html_report.append(f"<p><span style='color:red;'>Error: {e}</span></p>")

def get_hash_type(value):
    hash_types = {
        32: "MD5",
        40: "SHA1",
        60: "bcrypt",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512"
    }
    
    value_length = len(value)
    
    if value_length in hash_types.keys():
        return hash_types[value_length]
    else:
        return "Unknown"

def print_cookie(cookie, html_report):
    print("Cookie Name:", cookie.name)
    print("Cookie Value:", cookie.value)
    print("Cookie Hash Type:", get_hash_type(cookie.value))
    
    html_report.append(f"<p>Cookie Name: {cookie.name}</p>")
    html_report.append(f"<p>Cookie Value: {cookie.value}</p>")
    html_report.append(f"<p>Cookie Hash Type: {get_hash_type(cookie.value)}</p>")
    
    if cookie.get_nonstandard_attr('httponly'):
        print("HTTPOnly:", Fore.GREEN + Style.BRIGHT + "True" + Style.RESET_ALL)
        html_report.append(f"<p>HTTPOnly: <span style='color:green;'>True</span></p>")
    else:
        print("HTTPOnly:", Fore.RED + Style.BRIGHT + "False" + Style.RESET_ALL)
        html_report.append(f"<p>HTTPOnly: <span style='color:red;'>False</span></p>")
    
    if cookie.get_nonstandard_attr('samesite') is None:
        print("SameSite:", Fore.RED + Style.BRIGHT + "None" + Style.RESET_ALL)
        html_report.append(f"<p>SameSite: <span style='color:red;'>None</span></p>")
    else:
        print("SameSite:", Fore.GREEN + Style.BRIGHT + str(cookie.get_nonstandard_attr('samesite')) + Style.RESET_ALL)
        html_report.append(f"<p>SameSite: <span style='color:green;'>{cookie.get_nonstandard_attr('samesite')}</span></p>")
    
    if cookie.secure:
        print("Secure:", Fore.GREEN + Style.BRIGHT + "True" + Style.RESET_ALL)
        html_report.append(f"<p>Secure: <span style='color:green;'>True</span></p>")
    else:
        print("Secure:", Fore.RED + Style.BRIGHT + "False" + Style.RESET_ALL)
        html_report.append(f"<p>Secure: <span style='color:red;'>False</span></p>")
        
    print("---------------------------------------")
    html_report.append("<hr>")

def get_cookies_from_url(url, html_report):
    try:
        response = requests.get(url, verify=False)
        cookies = response.cookies

        if not cookies:
            print("Couldn't find any cookies to process.")
            html_report.append("<p>Couldn't find any cookies to process.</p>")
            return

        for cookie in cookies:
            print_cookie(cookie, html_report)

    except Exception as e:
        print("Error:", e)
        html_report.append(f"<p>Error: {e}</p>")

def get_technologies(url, html_report):
    try:
        result = subprocess.run(['wad', '-u', url], capture_output=True, text=True)
        if result.returncode == 0:
            technologies = json.loads(result.stdout)
            if technologies:
                print("Technologies used in the given website:")
                html_report.append("<div class='result'><h3>Technologies used:</h3>")
                
                for category, tech_list in technologies.items():
                    print(f"\n{category.capitalize()}:")
                    html_report.append(f"<h4>{category.capitalize()}:</h4>")
                    for tech_entry in tech_list:
                        app = tech_entry.get('app', 'Unknown Technology')
                        ver = tech_entry.get('ver', 'None')
                        type_ = tech_entry.get('type', 'Unknown Type')
                        print(f"Application: {app}\nVersion: {ver}\nType: {type_}\n")
                        html_report.append(f"""
                            <div class='tech-group'>
                                <p><strong>Application:</strong> {app}</p>
                                <p><strong>Version:</strong> {ver}</p>
                                <p><strong>Type:</strong> {type_}</p>
                            </div>
                        """)

                html_report.append("</div>")
                
                # Adding CVE search results section after technology detection
                html_report.append("<div class='result'><h3>CVE Entries</h3><div class='content'>")
                print("\nCVE Entries:")
                cve_found = False
                for category, tech_list in technologies.items():
                    for tech_entry in tech_list:
                        app = tech_entry.get('app', 'Unknown Technology')
                        ver = tech_entry.get('ver', 'None')
                        if ver and ver.lower() != 'none':
                            if search_cve(app, ver, html_report, max_results=10):  # Limit to 10 results
                                cve_found = True
                if not cve_found:
                    html_report.append("<p>No CVE entries found.</p>")
                html_report.append("</div></div>")

            else:
                print("No technologies found.")
                html_report.append("<div class='result'><h3>Technologies used:</h3><p>No technologies found.</p></div>")
            return technologies
        else:
            print("Error: Couldn't retrieve technologies.")
            html_report.append("<div class='result'><h3>Technologies used:</h3><p>Error: Couldn't retrieve technologies.</p></div>")
            return None

    except Exception as e:
        print(f"Error: {e}")
        html_report.append(f"<div class='result'><h3>Technologies used:</h3><p>Error: {e}</p></div>")
        return None

def fetch_cve_description(cve_link):
    try:
        response = requests.get(cve_link)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            description_tag = soup.find('div', {'id': 'GeneratedTable'}).find('td', {'colspan': '2'})
            if description_tag:
                return escape(description_tag.text.strip())
        return "Description not found."
    except Exception as e:
        return escape(str(e))

def search_cve(technology, version, html_report, max_results=10):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={technology}+{version}"
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find('div', {'id': 'TableWithRules'})
        
        if results:
            cve_entries = results.find_all('a', href=True)
            if cve_entries:
                print(f"\nCVE Entries for {technology} {version}:")
                html_report.append(f"<div class='cve-entry'><h4>CVE Entries for {technology} {version}:</h4><ul>")

                count = 0
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_cve = {executor.submit(fetch_cve_description, f"https://cve.mitre.org{cve['href']}"): cve for cve in cve_entries[:max_results]}
                    
                    for future in as_completed(future_to_cve):
                        cve = future_to_cve[future]
                        cve_code = cve.text.strip()
                        cve_link = f"https://cve.mitre.org{cve['href']}"
                        description = future.result()
                        
                        if technology.lower() in description.lower() and version.lower() in description.lower():
                            print(f"CVE: {cve_code}")
                            print(f"Link: {cve_link}")
                            print(f"Description: {description}\n")
                            
                            html_report.append(f"<li><strong>CVE:</strong> {cve_code}</li>")
                            html_report.append(f"<li><strong>Link:</strong> <a href='{cve_link}'>{cve_link}</a></li>")
                            html_report.append(f"<li><strong>Description:</strong> {description}</li>")
                            html_report.append("<hr>")
                            count += 1

                        if count >= max_results:
                            break

                if count == 0:
                    print("No relevant CVE entries found.")
                    html_report.append("<p>No relevant CVE entries found.</p>")
                
                html_report.append("</ul></div>")
                return True
            else:
                print("No CVE entries found.")
                html_report.append("<div class='cve-entry'><p>No CVE entries found.</p></div>")
                return False
        else:
            print("No CVE entries found.")
            html_report.append("<div class='cve-entry'><p>No CVE entries found.</p></div>")
            return False
    else:
        print(f"Error fetching data: {response.status_code}")
        html_report.append(f"<div class='cve-entry'><p>Error fetching data: {response.status_code}</p></div>")
        return False

        
def check_social_media_links(url, html_report):
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
                    html_report.append(f"<p>Checking {social_media.capitalize()} link: {social_media_url}</p>")
                    if social_media.lower() == "instagram":
                        check_instagram_link(social_media_url, html_report)
                    else:
                        check_social_media_link(social_media, social_media_url, user_agents, html_report)
                else:
                    print(f"No {social_media.capitalize()} link found.")
                    html_report.append(f"<p>No {social_media.capitalize()} link found.</p>")
        else:
            print(f"Failed to fetch page: {url}")
            html_report.append(f"<p>Failed to fetch page: {url}</p>")
            print("Unable to check social media links due to an error")
            html_report.append("<p>Unable to check social media links due to an error</p>")
    except requests.RequestException:
        print("Failed to fetch page. Please check the provided URL.")
        html_report.append("<p>Failed to fetch page. Please check the provided URL.</p>")
        print("Unable to check social media links due to an error")
        html_report.append("<p>Unable to check social media links due to an error</p>")

def check_social_media_link(social_media, url, user_agents, html_report):
    try:
        user_agent = random.choice(user_agents)
        response = requests.head(url, allow_redirects=True, headers={"User-Agent": user_agent})
        if response.status_code == 200:
            if social_media.lower() == "facebook":
                if "sorry, this page isn't available" in response.text.lower():
                    print("Broken Facebook Link")
                    html_report.append("<p>Broken Facebook Link</p>")
            elif social_media.lower() == "linkedin":
                if "this page doesn't exist" in response.text.lower():
                    print("Broken LinkedIn Link")
                    html_report.append("<p>Broken LinkedIn Link</p>")
            elif social_media.lower() == "twitter":
                if "this account doesn't exist" in response.text.lower():
                    print("Broken Twitter Link")
                    html_report.append("<p>Broken Twitter Link</p>")
            elif social_media.lower() == "github":
                if "there isn't a GitHub pages site here" in response.text.lower():
                    print("Broken Github Link")
                    html_report.append("<p>Broken Github Link</p>")
        else:
            print(f"Unable to check {social_media.capitalize()} link due to an error")
            html_report.append(f"<p>Unable to check {social_media.capitalize()} link due to an error</p>")
    except requests.RequestException:
        print(f"Unable to check {social_media.capitalize()} link due to an error")
        html_report.append(f"<p>Unable to check {social_media.capitalize()} link due to an error</p>")

def check_instagram_link(url, html_report):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            instagram_username = url.split('/')[-1]
            if instagram_username in soup.text:
                print("Instagram account exists")
                html_report.append("<p>Instagram account exists</p>")
            else:
                print(f"{bcolors.FAIL}{bcolors.BOLD}Broken Instagram Link{bcolors.ENDC}")
                html_report.append(f"<p><span style='color:red;'>Broken Instagram Link</span></p>")
        else:
            print("Failed to fetch page.")
            html_report.append("<p>Failed to fetch page.</p>")
    except requests.RequestException as e:
        print(f"Unable to check Instagram link due to an error: {e}")
        html_report.append(f"<p>Unable to check Instagram link due to an error: {e}</p>")

def check_cors_vulnerability(url, html_report):
    reflected_origins_response = requests.get(url, headers={"Origin": "https://attackerdomain.com"}, verify=False)
    if "https://attackerdomain.com" in reflected_origins_response.headers.get("Access-Control-Allow-Origin", "") and \
            "true" in reflected_origins_response.headers.get("Access-Control-Allow-Credentials", "").lower():
        print("\033[1m\033[921mReflected Origins Test: Potential CORS \033[0m")
        html_report.append("<p><span style='color:red;'>Reflected Origins Test: Potential CORS</span></p>")
    else:
        print("\033[1m\033[92mReflected Origins Test: No Potential CORS\033[0m")
        html_report.append("<p><span style='color:green;'>Reflected Origins Test: No Potential CORS</span></p>")

    attacker_domain = url.split("//")[1].split("/")[0]
    trusted_subdomains_response = requests.get(url, headers={"Origin": f"https://attacker.{attacker_domain}"}, verify=False)
    if trusted_subdomains_response.headers.get("Access-Control-Allow-Origin", ""):
        print("\033[1m\033[91mTrusted Subdomains Test: Potential CORS\033[0m")
        html_report.append("<p><span style='color:red;'>Trusted Subdomains Test: Potential CORS</span></p>")
    else:
        print("\033[1m\033[92mTrusted Subdomains Test: No Potential CORS\033[0m")
        html_report.append("<p><span style='color:green;'>Trusted Subdomains Test: No Potential CORS</span></p>")

    null_origin_response = requests.get(url, headers={"Origin": "null"}, verify=False)
    if "null" in null_origin_response.headers.get("Access-Control-Allow-Origin", "") and \
            "true" in null_origin_response.headers.get("Access-Control-Allow-Credentials", "").lower():
        print("\033[1m\033[91mNull Origin Test: Potential CORS\033[0m")
        html_report.append("<p><span style='color:red;'>Null Origin Test: Potential CORS</span></p>")
    else:
        print("\033[1m\033[92mNull Origin Test: No Potential CORS\033[0m")
        html_report.append("<p><span style='color:green;'>Null Origin Test: No Potential CORS</span></p>")

def scan_popular_ports(url, html_report):
    try:
        url_hostname = urlparse(url).hostname
            
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
                    result = s.connect_ex((url_hostname, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception as e:
                print(f"Error: {e}")
                html_report.append(f"<p>Error: {e}</p>")

        for port in open_ports:
            print(f"Port {port} is open")
            html_report.append(f"<p>Port {port} is open</p>")

    except Exception as e:
        print(f"Error: {e}")
        html_report.append(f"<p>Error: {e}</p>")

def check_spf(domain, html_report):
    try:
        domain = domain.split("//")[-1].split("/")[0]
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.strings
            for record in txt_record:
                if record.decode().startswith("v=spf"):
                    return True
        return False
    except dns.resolver.NoAnswer:
        return False

def check_dmarc(domain, html_report):
    try:
        domain = domain.split("//")[-1].split("/")[0]
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

def clickjacking(url, html_report):
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
        html_report.append("<p>HTML file generated: clickjack_test.html</p>")
        return True

from urllib.parse import urlparse
import os

from urllib.parse import urlparse
import os

def get_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    urls = [url.strip() for url in urls]
    domains = [urlparse(url).netloc for url in urls]
    return domains
    
def save_html_report(report, filename, domains):
    is_single_domain = len(domains) == 1
    sidebar_links = "" if is_single_domain else "".join([f'<a href="#domain-{i}">{domain}</a>' for i, domain in enumerate(domains)])
    content_sections = "".join([f'<div id="domain-{i}" class="content">{report[i]}</div>' for i in range(len(report))])

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f4f4f9;
                color: #333;
                margin: 0;
                padding: 0;
                display: flex;
                height: 100vh;
                overflow: hidden;
            }}
            .sidebar {{
                width: 210px;
                background: #333;
                color: white;
                padding: 20px;
                box-shadow: 2px 0 5px rgba(0, 0, 0, 0.1);
                height: 100%;
                overflow-y: auto;
                z-index: 1000;
                position: fixed;
                transition: transform 0.3s ease, width 0.3s ease;
                transform: translateX(0);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                left: 0;
            }}
            .sidebar.collapsed {{
                transform: translateX(-250px);
                width: 230px;
            }}
            .sidebar h2 {{
                font-size: 18px;
                margin-bottom: 20px;
                text-align: center;
                color: white;
            }}
            .sidebar a {{
                color: white;
                text-decoration: none;
                display: block;
                padding: 10px 0;
                transition: background 0.3s;
            }}
            .sidebar a:hover {{
                background: #575757;
            }}
            .sidebar .footer {{
                text-align: center;
                padding: 20px;
                font-size: 12px;
                color: #666;
                margin-top: auto;
            }}
            .sidebar .footer a {{
                color: #4CAF50;
                text-decoration: none;
            }}
            .sidebar-toggle {{
                position: fixed;
                top: 20px;
                left: 220px;
                background: #333;
                color: white;
                border: none;
                padding: 10px;
                cursor: pointer;
                z-index: 1001;
                transition: left 0.3s ease;
            }}
            .sidebar.collapsed + .sidebar-toggle {{
                left: 0;
            }}
            .content-container {{
                padding: 20px;
                flex-grow: 1;
                overflow: auto;
                background: white;
                margin-left: 250px;
                position: relative;
                z-index: 0;
                transition: margin-left 0.3s ease;
            }}
            .sidebar.collapsed + .sidebar-toggle + .content-container {{
                margin-left: 0;
            }}
            h1, h2, h3 {{
                color: #333;
                margin-bottom: 20px;
                border-bottom: 2px solid #e0e0e0;
                padding-bottom: 10px;
            }}
            h4 {{
                color: #333;
                margin-bottom: 10px;
                border-bottom: 1px solid #e0e0e0;
                padding-bottom: 5px;
            }}
            p {{
                line-height: 1.6;
                margin-bottom: 10px;
            }}
            .header {{
                background-color: #4CAF50;
                color: white;
                padding: 10px 0;
                text-align: center;
                border-radius: 8px 8px 0 0;
                margin-bottom: 20px;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .green {{
                color: green;
            }}
            .red {{
                color: red;
            }}
            .highlight {{
                background: #fffbcc;
                padding: 5px;
                border-radius: 5px;
                border-left: 5px solid #ffeb3b;
            }}
            .result {{
                margin-bottom: 20px;
                padding: 15px;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background: #fafafa;
            }}
            .result h3 {{
                margin-top: 0;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 10px;
                background: #f4f4f9;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
            }}
            .result h3 .title {{
                flex-grow: 1;
            }}
            .result h3 .toggle-icon {{
                font-size: 14px;
                margin-left: 10px;
            }}
            .footer {{
                text-align: center;
                padding: 20px;
                font-size: 12px;
                color: #666;
                margin-top: auto;
            }}
            .footer a {{
                color: #4CAF50;
                text-decoration: none;
            }}
            .tech-group {{
                margin-bottom: 20px;
            }}
            .tech-group p {{
                margin: 5px 0;
            }}
            .content {{
                display: none;
            }}
            .content.active {{
                display: block;
                margin-top: 10px;
                padding: 10px;
                background: #fff;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
            }}
            .cve-entry {{
                margin-bottom: 10px;
                padding: 10px;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background: #fff;
            }}
            .cve-entry h4 {{
                margin-top: 0;
            }}
            .cve-entry ul {{
                list-style-type: disc;
                padding-left: 20px;
            }}
            .cve-entry ul li {{
                margin-bottom: 5px;
            }}
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', (event) => {{
                const contents = document.querySelectorAll('.content');
                const domainLinks = document.querySelectorAll('.sidebar a');

                domainLinks.forEach((link, index) => {{
                    link.addEventListener('click', (e) => {{
                        e.preventDefault();
                        contents.forEach(content => {{
                            content.classList.remove('active');
                        }});
                        document.getElementById('domain-' + index).classList.add('active');
                    }});
                }});

                // Show the first domain by default
                if (contents.length > 0) {{
                    contents[0].classList.add('active');
                }}

                const headers = document.querySelectorAll('.result h3');
                headers.forEach(header => {{
                    const toggleIcon = header.querySelector('.toggle-icon');
                    header.addEventListener('click', () => {{
                        const content = header.nextElementSibling;
                        const isOpen = content.style.display === 'block';
                        content.style.display = isOpen ? 'none' : 'block';
                        toggleIcon.textContent = isOpen ? '+' : '-';
                    }});
                }});

                const sidebar = document.querySelector('.sidebar');
                const toggleButton = document.querySelector('.sidebar-toggle');

                if (sidebar && toggleButton) {{
                    toggleButton.addEventListener('click', () => {{
                        sidebar.classList.toggle('collapsed');
                        if (sidebar.classList.contains('collapsed')) {{
                            toggleButton.style.left = '0';
                        }} else {{
                            toggleButton.style.left = '250px';
                        }}
                    }});
                }}
            }});
        </script>
    </head>
    <body>
        {'<div class="sidebar"><h2>Scanned Domains</h2>' + sidebar_links + '<div class="footer"><p>Report generated by <a href="https://github.com/redhotchilihacker1/Mergen">Mergen</a></p></div></div>' if not is_single_domain else ""}
        {'<button class="sidebar-toggle">☰</button>' if not is_single_domain else ""}
        <div class="content-container">
            <div class="header">
                <h1>Security Scan Report</h1>
            </div>
            {content_sections}
        </div>
    </body>
    </html>
    """
    with open(filename, 'w') as file:
        file.write(html_template)
    report_path = os.path.abspath(filename)
    print(f"HTML report saved to: {report_path}")
    print(f"Open the report at: file://{report_path}")
    
def check_response_info(url, html_report):
    try:
        response = requests.get(url, verify=False)
        status_code = response.status_code
        headers = response.headers

        # Information Disclosure Vulnerability Check
        info_disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        vulnerabilities = {}

        for header, value in headers.items():
            if header.lower() in info_disclosure_headers:
                vulnerabilities[header] = value

        # Terminal output
        print(f"\nResponse Information for {url}:")
        print(f"{'='*40}")
        print(f"Status Code: {status_code}")
        print(f"{'-'*40}")
        print("Headers:")
        for header, value in headers.items():
            if header in vulnerabilities:
                print(f"\033[91m\033[1m{header}: {value}\033[0m")  # Bold red in terminal
            else:
                print(f"{header}: {value}")
        print(f"\n{'='*40}")

        if vulnerabilities:
            print(f"\nInformation Disclosure Vulnerabilities found in headers for {url}:")
            for header, value in vulnerabilities.items():
                print(f"\033[91m\033[1m{header}: {value}\033[0m")  # Bold red in terminal
            print(f"\n{'='*40}")

        # HTML report output
        html_report.append("<div class='result'><h3>Response Information</h3>")
        html_report.append(f"<p><strong>Status Code:</strong> {status_code}</p>")
        html_report.append("<p><strong>Headers:</strong></p>")
        html_report.append("<ul>")
        for header, value in headers.items():
            if header in vulnerabilities:
                html_report.append(f"<li><strong style='color:red;'>{header}:</strong> {value}</li>")  # Bold red in HTML
            else:
                html_report.append(f"<li><strong>{header}:</strong> {value}</li>")
        html_report.append("</ul>")
        
        if vulnerabilities:
            html_report.append("<p><strong>Information Disclosure Vulnerabilities:</strong></p>")
            html_report.append("<ul>")
            for header, value in vulnerabilities.items():
                html_report.append(f"<li><strong style='color:red;'>{header}:</strong> {value}</li>")  # Bold red in HTML
            html_report.append("</ul>")
        
        html_report.append("</div>")
    except Exception as e:
        # Terminal output
        print(f"Error retrieving response information for {url}: {e}")

        # HTML report output
        html_report.append(f"<p><strong>Error:</strong> {e}</p>")

def check_default_page(url, html_report):
    try:
        response = requests.get(url, allow_redirects=False)

        if response.status_code in [301, 302]:
            redirect_url = response.headers.get('Location')
            print(f"Redirected to: {redirect_url}")
            html_report.append(f"<p>Redirected to: {redirect_url}</p>")
            return False, f"Redirected to: {redirect_url}"

        if response.status_code == 200:
            content = response.text.lower()
            default_page_indicators = [
                "welcome to nginx",
                "it works!",
                "apache2 ubuntu default page",
                "iis windows server",
                "index of /",
                "default web site page",
                "test page for apache installation",
                "congratulations! your website is up and running.",
                "this is the default welcome page",
                "nginx on debian",
                "your new web server is ready to use.",
                "the web server software is running but no content has been added",
                "default home page",
                "this page is used to test the proper operation of the apache http server",
                "your apache installation is working properly",
                "powered by centos",
                "this is a placeholder for the home page",
                "default page",
                "web server default page",
                "this is the default index page of a new domain",
                "your hosting is set up"
            ]
            
            for indicator in default_page_indicators:
                if f">{indicator}<" in content or f" {indicator} " in content:
                    html_report.append(f"<p>Found default page indicator: '{indicator}'</p>")
                    print(f"Found default page indicator: '{indicator}'")
                    return True, f"Found default page indicator: '{indicator}'"
        
        return False, "No default page indicator found."
    except requests.RequestException as e:
        html_report.append(f"<p>Error occurred: {str(e)}</p>")
        print(f"Error occurred: {str(e)}")
        return False, f"Error occurred: {str(e)}"


def take_screenshot(url):
    # Remove "http://" or "https://" from the URL for the file name
    file_name = url.replace("http://", "").replace("https://", "").replace("/", "_")
    file_path = f"{file_name}.png"

    # Set up Selenium with Chrome
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        driver.get(url)
        driver.save_screenshot(file_path)
        with open(file_path, "rb") as image_file:
            base64_image = base64.b64encode(image_file.read()).decode('utf-8')
        os.remove(file_path)  # Remove the temporary file
        return base64_image
    except Exception as e:
        print(f"Error taking screenshot for {url}: {e}")
        return None
    finally:
        driver.quit()

def reverse_ip_lookup(url, html_report):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        ip_address = socket.gethostbyname(urlparse(url).hostname)
        print(f"IP Address: {ip_address}")
        html_report.append("<div class='result'><h3><span class='title'>Reverse IP Lookup</span><span class='toggle-icon'>+</span></h3>")
        html_report.append("<div class='content'>")

        try:
            reverse_dns_api = "https://domains.yougetsignal.com/domains.php"
            response = requests.post(reverse_dns_api, data={'remoteAddress': ip_address}, headers=headers)
            if response.status_code == 200:
                data = response.json()
                domains = data.get('domainArray', [])
                if domains:
                    print(f"\nDomains hosted on the same server as {url}:")
                    html_report.append("<ul>")
                    for domain_info in domains[:20]:  # Limit to first 20 results
                        domain = domain_info[0]
                        if domain != url:
                            print(domain)
                            html_report.append(f"<li>{domain}</li>")
                    html_report.append("</ul>")
                    restriction_message = "\nThis is a restricted result because of the limitation. Check out yougetsignal.com website to get more information."
                    print(restriction_message)
                    html_report.append(f"<p>{restriction_message}</p>")
                    print("\n")
                else:
                    print(f"No other domains found hosted on the same server as {url}.")
                    html_report.append(f"<p>No other domains found hosted on the same server as {url}.</p>")
            else:
                print(f"Error: Could not perform reverse IP lookup for {url}.")
                html_report.append("<p>Error: Could not perform reverse IP lookup for {url}.</p>")
        except Exception as e:
            print(f"Error: {e}")
            html_report.append(f"<p>Error: {e}</p>")

        html_report.append("</div></div>")
    except Exception as e:
        print(f"Error: {e}")
        html_report.append(f"<div class='result'><h3><span class='title'>Reverse IP Lookup</span><span class='toggle-icon'>+</span></h3>")
        html_report.append(f"<div class='content'><p>Error: {e}</p></div></div>")

        
def main():
    try:
        parser = argparse.ArgumentParser(description="This script performs various security checks on a given website.")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--url", nargs="*", type=str, help="URL of the website to be analyzed")
        group.add_argument("--file", type=str, help="File containing URLs to be analyzed")
        parser.add_argument("--cookie", action="store_true", help="Enable checking of cookie values")
        parser.add_argument("--method", action="store_true", help="Check which HTTP Debugging methods are enabled")
        parser.add_argument("--headers", action="store_true", help="Enable checking of security headers")
        parser.add_argument("--ssl", action="store_true", help="Enable checking of SSL/TLS versions")
        parser.add_argument("--tech", action="store_true", help="Identify web technologies used")
        parser.add_argument("--social", action="store_true", help="Check social media links on the website")
        parser.add_argument("--cors", action="store_true", help="Check for CORS vulnerabilities on the website")
        parser.add_argument("--ports", action="store_true", help="Scan for popular ports")
        parser.add_argument("--spf", action="store_true", help="Perform SPF policy check")
        parser.add_argument("--dmarc", action="store_true", help="Perform DMARC policy check")
        parser.add_argument("--cjacking", action="store_true", help="Perform clickjacking vulnerability check")
        parser.add_argument("--response", action="store_true", help="Get response information without source code")
        parser.add_argument("--sshot", action="store_true", help="Take a screenshot of the website")
        parser.add_argument("--default", action="store_true", help="Check for default welcome pages")
        parser.add_argument("--reverse", action="store_true", help="Perform reverse IP lookup")
        parser.add_argument("--all", action="store_true", help="Perform all checks")
        parser.add_argument("--output", type=str, help="Output HTML report to the specified file")

        args = parser.parse_args()
        
        html_reports = []  # Her domain için ayrı HTML raporu
        domains = []  # Taranan domain'ler listesi

        if args.all and (args.cookie or args.method or args.headers or args.ssl or args.tech or args.social or args.cors or args.ports or args.spf or args.dmarc or args.cjacking or args.response or args.welcome or args.reverse):
            parser.error("--all flag can only be used with --file and --url flags")

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
            domains.append(url)  # Domain listesine ekleme
            domain_html_report = []  # Bu domain için HTML raporu

            ip_address = socket.gethostbyname(urlparse(url).hostname)
            hostname = urlparse(url).hostname

            start_time = datetime.now()

            print(f"IP Address: {ip_address}")
            print(f"Hostname: {hostname}")
            print(f"Scan Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

            domain_html_report.append(f"<p><strong>IP Address:</strong> {ip_address}</p>")
            domain_html_report.append(f"<p><strong>Hostname:</strong> {hostname}</p>")
            domain_html_report.append(f"<p><strong>Scan Start Time:</strong> {start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>")

            if args.ssl or args.all:
                print_banner_with_border("SSL/TLS Versions")
                domain_html_report.append("<div class='result'><h3><span class='title'>SSL/TLS Versions</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                check_ssl_versions(url, domain_html_report)
                check_sslv2_support(url, domain_html_report)
                check_sslv3_support(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.cookie or args.all:
                print_banner_with_border("Cookie Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>Cookie Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                get_cookies_from_url(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.headers or args.all:
                print_banner_with_border("Security Headers")
                domain_html_report.append("<div class='result'><h3><span class='title'>Security Headers</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                check_security_headers(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.method or args.all:
                print_banner_with_border("HTTP Debugging Methods")
                domain_html_report.append("<div class='result'><h3><span class='title'>HTTP Debugging Methods</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                check_debugging_enabled(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.tech or args.all:
                print_banner_with_border("Web Technologies")
                domain_html_report.append("<div class='result'><h3><span class='title'>Web Technologies</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                get_technologies(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.social or args.all:
                print_banner_with_border("Broken Link Hijack Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>Broken Link Hijack Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                check_social_media_links(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.cors or args.all:
                print_banner_with_border("CORS Misconfigurations")
                domain_html_report.append("<div class='result'><h3><span class='title'>CORS Misconfigurations</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                check_cors_vulnerability(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.ports or args.all:
                print_banner_with_border("Port Scan")
                domain_html_report.append("<div class='result'><h3><span class='title'>Port Scan</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                scan_popular_ports(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            if args.spf or args.all:
                print_banner_with_border("SPF Policy Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>SPF Policy Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                spf_result = check_spf(url, domain_html_report)
                if spf_result:
                    print(f"{Fore.GREEN + Style.BRIGHT}SPF record have been found{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:green;'>SPF record have been found</span></p>")
                else:
                    print(f"{Fore.RED + Style.BRIGHT}SPF record have not been found{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:red;'>SPF record have not been found</span></p>")
                domain_html_report.append("</div></div>")
                print("\n")

            if args.dmarc or args.all:
                print_banner_with_border("DMARC Policy Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>DMARC Policy Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                dmarc_result = check_dmarc(url, domain_html_report)
                if dmarc_result:
                    print(f"{Fore.GREEN + Style.BRIGHT}DMARC record have been found{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:green;'>DMARC record have been found</span></p>")
                else:
                    print(f"{Fore.RED + Style.BRIGHT}DMARC record have not been found{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:red;'>DMARC record have not been found</span></p>")
                domain_html_report.append("</div></div>")
                print("\n")

            if args.cjacking or args.all:
                print_banner_with_border("Clickjacking Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>Clickjacking Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                cjacking_result = clickjacking(url, domain_html_report)
                if cjacking_result:
                    print(f"{Fore.RED + Style.BRIGHT}Possible Clickjacking vulnerability.{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:red;'>Possible Clickjacking vulnerability.</span></p>")
                else:
                    print(f"{Fore.GREEN + Style.BRIGHT}Clickjacking vulnerability not found.{Style.RESET_ALL}")
                    domain_html_report.append("<p><span style='color:green;'>Clickjacking vulnerability not found.</span></p>")
                domain_html_report.append("</div></div>")
                print("\n")
                
            if args.response or args.all:
                domain_html_report.append("<div class='result'><h3><span class='title'>Response Information</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                print_banner_with_border("Response Information")
                check_response_info(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")
                
            if args.sshot or args.all:
                print_banner_with_border("Screenshot")
                domain_html_report.append("<div class='result'><h3><span class='title'>Screenshot</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                base64_image = take_screenshot(url)
                if base64_image:
                    domain_html_report.append(f"<p><strong>Screenshot:</strong></p>")
                    domain_html_report.append(f"<img src='data:image/png;base64,{base64_image}' alt='Screenshot of {url}' style='width: 100%; max-width: 600px;'>")
                else:
                    domain_html_report.append("<p><strong>Screenshot could not be taken.</strong></p>")
                domain_html_report.append("</div></div>")
                print("\n")

            if args.default or args.all:
                print_banner_with_border("Default Welcome Page Check")
                domain_html_report.append("<div class='result'><h3><span class='title'>Default Welcome Page Check</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                is_vulnerable, message = check_default_page(url, domain_html_report)
                print(f"Is vulnerable: {is_vulnerable}\nMessage: {message}")
                domain_html_report.append(f"<p>{message}</p>")
                domain_html_report.append("</div></div>")
                print("\n")
            
            if args.reverse or args.all:
                print_banner_with_border("Reverse IP Lookup")
                domain_html_report.append("<div class='result'><h3><span class='title'>Reverse IP Lookup</span><span class='toggle-icon'>+</span></h3>")
                domain_html_report.append("<div class='content'>")
                reverse_ip_lookup(url, domain_html_report)
                domain_html_report.append("</div></div>")
                print("\n")

            end_time = datetime.now()
            print(f"Scan End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            total_time = end_time - start_time
            total_seconds = round(total_time.total_seconds(), 1)
            print("Total Scan Time:", total_seconds, "seconds.\n\n\n")

            domain_html_report.append(f"<p><strong>Scan End Time:</strong> {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>")
            domain_html_report.append(f"<p><strong>Total Scan Time:</strong> {total_seconds} seconds.</p><br><br>")

            html_reports.append("".join(domain_html_report))

        if args.output:
            save_html_report(html_reports, args.output, domains)

    except KeyboardInterrupt:
        print(f"{bcolors.FAIL + bcolors.BOLD}The scan has been terminated by the user.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
