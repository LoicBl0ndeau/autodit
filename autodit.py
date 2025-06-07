#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sys
import argparse
import webbrowser
import requests
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from ftplib import FTP
from colorama import just_fix_windows_console
just_fix_windows_console()

requests.packages.urllib3.disable_warnings()

AsciiArt = r"""
      ___           ___                      ___                                             
     /\  \         /\  \                    /\  \         _____                              
    /::\  \        \:\  \         ___      /::\  \       /::\  \       ___           ___     
   /:/\:\  \        \:\  \       /\__\    /:/\:\  \     /:/\:\  \     /\__\         /\__\    
  /:/ /::\  \   ___  \:\  \     /:/  /   /:/  \:\  \   /:/  \:\  \   /:/__/        /:/  /    
 /:/_/:/\:\__\ /\  \  \:\__\   /:/__/   /:/__/ \:\__\ /:/__/ \:\__\ /::\  \       /:/__/     
 \:\/:/  \/__/ \:\  \ /:/  /  /::\  \   \:\  \ /:/  / \:\  \ /:/  / \/\:\  \__   /::\  \     
  \::/__/       \:\  /:/  /  /:/\:\  \   \:\  /:/  /   \:\  /:/  /     \:\/\__\ /:/\:\  \    
   \:\  \        \:\/:/  /   \/__\:\  \   \:\/:/  /     \:\/:/  /       \::/  / \/  \:\  \   
    \:\__\        \::/  /         \:\__\   \::/  /       \::/  /        /:/  /       \:\__\  
     \/__/         \/__/           \/__/    \/__/         \/__/         \/__/         \/__/  
"""
print(AsciiArt)

class colors:
    # Regular Colors
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    # Bold
    BOLD = '\033[1m'
    # Reset
    RESET = '\033[0m'

summary = []

def parse_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for host in root.findall('host'):
        ip = host.find('address').attrib['addr']
        ports = []
        for port in host.findall('ports/port'):
            portid = port.attrib['portid']
            state = port.find('state').attrib['state']
            if state == 'open':
                ports.append(portid)
        res_nmap.append([ip] + ports)

def check_anonymous_login(ip_address):
    try:
        ftp = FTP()
        ftp.connect(ip_address, 21)
        response = ftp.login('anonymous', 'mozilla@example.com')
        banner = ftp.getwelcome()
        if '230' in response:
            ftp_rights_log = colors.BOLD + colors.GREEN + "[+] Anonymous READ/WRITE on " + ip_address + " - " + banner + colors.RESET
            summary.append(ftp_rights_log)
        elif '530' in response:
            ftp_rights_log = colors.BOLD + colors.GREEN + "[+] Anonymous READ on " + ip_address + " - " + banner + colors.RESET
            summary.append(ftp_rights_log)
        else:
            ftp_rights_log = colors.RED+"[-] No ftp anonymous login on "+ ip_address + " - " + banner + colors.RESET
    except:
        ftp_rights_log = colors.RED+"[-] Error while trying ftp anonymous login on "+ ip_address + colors.RESET
    print(ftp_rights_log)

def scrapForm(url, https_possible):
    # Removes SSL Issues With Chrome
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--ignore-certificate-errors-spki-list')
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.add_argument('--disable-notifications')
    options.add_argument('--headless') # Comment to view browser actions

    driver = webdriver.Chrome(options=options)
    potential_input_password = []
    potential_input_username = []
    potential_input_submit = []
    try:
        driver.get(url)
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'form input')))
        redirected_url = driver.current_url
        inputs = driver.find_elements(By.CSS_SELECTOR, 'form input')

        for i in inputs: #get potential input 
            input_type = str(i.get_attribute('type')).lower()
            if str(i.get_attribute('disabled')).lower() != 'true' and str(i.value_of_css_property('display')).lower() != 'none' and str(i.get_attribute('name')).lower() != '':
                if input_type == 'password':
                    potential_input_password.append(i)
                elif input_type == 'submit':
                    potential_input_submit.append(i)
                elif any(x in input_type for x in ['text', 'email', 'number', 'tel', 'url', 'search']):
                    potential_input_username.append(i)
    except Exception:
        print(colors.RED+"[-] No form found on " + url + colors.RESET)
        if https_possible:
            scrapForm(url.replace("http://", "https://"), False)
    finally:
        if len(potential_input_password) != 1 or len(potential_input_username) > 1 or len(potential_input_submit) > 1:
            print(colors.RED+"[-] Unable to brute-force on " + url + colors.RESET)
            webbrowser.open(url)
        else:
            potential_input_username = None if len(potential_input_username) == 0 else potential_input_username[0]
            potential_input_submit = None if len(potential_input_submit) == 0 else potential_input_submit[0]
            send(redirected_url, potential_input_username, potential_input_password[0], potential_input_submit)
            driver.quit()

def send(redirected_url, input_username, input_password, input_submit):
    with open(args.wordlist, 'r') as f:
        found = False
        for logins in f.read().split("\n\n"):
            username = logins.split("\n")[0]
            password = logins.split("\n")[1]
            if(input_username == None and input_submit == None):
                payload = {input_password.get_attribute('name'): password}
            elif(input_username == None):
                payload = {input_password.get_attribute('name'): password, input_submit.get_attribute('name'): input_submit.get_attribute('value')}
            elif(input_submit == None):
                payload = {input_username.get_attribute('name'): username, input_password.get_attribute('name'): password}
            else:
                payload = {input_username.get_attribute('name'): username, input_password.get_attribute('name'): password, input_submit.get_attribute('name'): input_submit.get_attribute('value')}
            session = requests.Session()
            try:
                r = session.post(redirected_url, headers={'User-Agent': args.agent}, data=payload, verify=False)
                r = session.get(r.url, headers={'User-Agent': args.agent}, verify=False)
                if r.url != redirected_url:
                    if input_username == None:
                        log = colors.BOLD + colors.GREEN + "[+] Login found on " + url + " : " + password + colors.RESET
                    else:
                        log = colors.BOLD + colors.GREEN + "[+] Login found on " + url + " : " + username + " / " + password + colors.RESET
                    summary.append(log)
                    print(log)
                    found = True
                    break
            except:
                print(colors.RED+"[-] Unable to send post request to " + redirected_url + colors.RESET)
                webbrowser.open(redirected_url)
                break
        if not found:
            print(colors.RED+"[-] No login found on " + url + colors.RESET)

parser = argparse.ArgumentParser(description="Autodit by 123CS")
parser.add_argument('--xml', help="Your nmap xml output.", required=True)
parser.add_argument('--agent', help="User agent string to send the login as. Default : Agent:Mozilla/5.0", default="Mozilla/5.0", required=False)
parser.add_argument('--wordlist', help="Name of the wordlist file to use. It must be in the format : login1 \\n password1 \\n\\n login2 \\n password2. If no wordlist is provided, brute-force is skipped and webpages opened.", required=False)
args = parser.parse_args()

res_nmap = []
parse_xml(args.xml)

print("[*] Nmap XML well parsed")
if args.wordlist == None:
    brute_force = False
    print("[*] No wordlist provided, skipping brute-force")
else:
    try:
        with open(args.wordlist, 'r') as f:
            pass
    except:
        print(colors.RED+"[-] Wordlist file not found"+colors.RESET)
        sys.exit(1)
    brute_force = True
    print("[*] User-Agent: " + args.agent)
    print("[*] Wordlist: " + args.wordlist)

smb = [] #445
alternative_ports = []
for machine in res_nmap:
    ip_address = machine[0]
    for port in machine[1:]:
        if port == '21':
            check_anonymous_login(ip_address)
        elif port == '80':
            if '443' in machine[1:]:
                url = "https://"+ip_address
                https_possible = True
            else:
                https_possible = False
                url = "http://"+ip_address
            if brute_force:
                scrapForm(url, https_possible)
            else:
                webbrowser.open(url)
        elif port == '443' and '80' not in machine[1:]:
            url = "https://"+ip_address
            if brute_force:
                scrapForm(url, https_possible)
            else:
                webbrowser.open(url)
        elif port == '8000' or port == '8080' or port == '8443':
            alternative_ports.append(ip_address+':'+port)
        elif port == '445':
            smb.append(ip_address)

if alternative_ports:
    print("\n[*] Interesting alternative opened ports (try https if no results):")
    print("\n".join(alternative_ports))

if smb:
    print("\n[*] IP addresses with port 445 opened (scan them with smbmap and ms17 with metasploit):")
    print(" ".join(smb))

print("\n\n[*] Summary:")
if len(summary) == 0:
    print("Nothing found")
else:
    for log in summary:
        print(log)
print("\n")