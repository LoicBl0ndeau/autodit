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


def scrapForm():
    # Removes SSL Issues With Chrome
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--ignore-certificate-errors-spki-list')
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.add_argument('--disable-notifications')
    #options.add_argument('--headless') # Comment to view browser actions

    driver = webdriver.Chrome(options=options)
    potential_input_password = []
    potential_input_username = []
    try:
        driver.get(url)
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'form input')))
        inputs = driver.find_elements(By.CSS_SELECTOR, 'form input')

        for i in inputs: #get potential input 
            input_type = str(i.get_attribute('type')).lower()
            if str(i.get_attribute('disabled')).lower() != 'true' and str(i.value_of_css_property('display')).lower() != 'none' and str(i.get_attribute('name')).lower() != '':
                if input_type == 'password':
                    potential_input_password.append(i)
                elif any(x in input_type for x in ['text', 'email', 'number', 'tel', 'url', 'search']):
                    potential_input_username.append(i)
    except Exception:
        print("[-] No form found on " + url)
    finally:
        driver.quit()

        if len(potential_input_password) != 1 or len(potential_input_username) > 1:
            print("[-] Unable to brute-force on " + url)
            webbrowser.open(url)
        else:
            print(len(potential_input_password), len(potential_input_username))
            #send(potential_input_username[0], potential_input_password[0])

def send(username, password):
    payload = {'username': username, 'password': password}
    r = requests.post(url, {'User-Agent': args.agent}, payload)
    if "invalid" in r.text or "incorrect" in r.text:
        print("[+] Correct logins: " + username+"/"+password+" on " + url)

parser = argparse.ArgumentParser(description="Autodit by 123CS")
parser.add_argument('--ip', help="IP class to scan (searching in /24)", required=True)
parser.add_argument('--agent', help="User agent string to send the login as. Default : Agent:Mozilla/5.0", default="Agent:Mozilla/5.0", required=False)
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

    res_nmap = output.decode("utf-8")
else: #FOR DEV
    with open(args.ip+"-24.g", 'r') as f: #FOR DEV
        res_nmap = f.read() #FOR DEV

print("[*] User-Agent: " + args.agent)
print("[*] Wordlist: " + args.wordlist)

for line in res_nmap.split('\n'):
    if "80/open" in line or "443/open" in line:
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line).group()
        if "https" in line:
            url = "https://"+ip_match
        else:
            url = "http://"+ip_match
        #webbrowser.open(url)

        print("[*] URL: " + url)
        scrapForm()
        with open("wordlist.txt", 'r') as f:
            for logins in f.read().split("\n\n"):
                username = logins.split("\n")[0]
                password = logins.split("\n")[1]