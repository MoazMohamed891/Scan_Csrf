import requests
import os
import sys
import sys
import time
##############################################################################################
print ("\033[31m")

os.system("figlet Hallo To Moaz Mohamed Script")

time.sleep(3)

os.system("clear")


print ("\033[1;31m")

print ("#"*67)

print ("\033[1;34m")

os.system('figlet Scan CSRF ')

print ("\033[1;31m")

print ("\033[35m")
print (" \033[93;5m⚡\033[0m \033[35mBY.Moaz Mohamed\033[93;5m ⚡\033[0m")
print ("\033[36m")
print ("Github : https://github.com/MoazMohamed891")
print ("Linkedin : https://www.linkedin.com/in/moaaz-mohamed-hassan-07604a348")
print ("\033[1;31m")

print ("#"*67)
##############################################################

print ("\033[1;34m")

# List of 300 CSRF payloads to test
csrf_payloads = [
    '123456', 'abcdef', 'qwerty', 'csrf123', '098765', '1a2b3c', 'csrf_token', 'csrf', 'token123', 'sec_token', 
    'abc123', 'xyz987', 'CSRF-TOKEN', 'token_123', 'token', 'my_csrf_token', 'csrf_test', 'csrf1234', 'token_1', 
    'csrf_token_123', 'csrf12345', 'token_secret', 'session_token', 'auth_csrf_token', 'csrfkey', 'token@123', 
    'csrf_code', 'csrf_token_value', 'random_token', 'csrf_secure', 'session_csrf', 'csrf_security', 'csrf_id', 
    'csrf_validation', 'csrf123abc', 'csrf_cookie', 'test_csrf_token', 'csrf_session', 'csrf_secret', 'unique_token', 
    'csrf_token_1', 'verify_token', 'user_csrf', 'csrf_test123', 'csrfhash', 'csrf_random', 'form_csrf_token', 
    'csrf_key', 'my_csrf_key', 'token_id', 'csrf_validation_token', 'csrf_security_token', 'csrf_token_test', 
    'token1234', 'csrf_verify', 'csrf_code123', 'token_value', 'app_csrf_token', 'csrf_authentication', 'csrf_value', 
    'csrf_secure_token', 'csrf_validation_code', 'csrf_form_token', 'auth_token', 'csrf_security_key', 'csrfid', 
    'session_csrf_token', 'secure_token', 'csrf_id_token', 'session_csrf_key', 'csrf_authentication_token', 
    'token_csrf', 'validate_csrf_token', 'csrf_check', 'token_secret123', 'csrf_form', 'token_csrf123', 
    'csrf_session_token', 'csrf_form_key', 'random_csrf_token', 'token_auth', 'token_verify', 'csrfauth', 
    'csrf_secure_key', 'csrf_data', 'csrf_verify_token', 'csrf_form_id', 'csrf_code_value', 'csrf_token_key', 
    'token_secure', 'csrf123token', 'csrf_authentication_code', 'form_csrf', 'session_csrf_id', 'csrf_cookie_token', 
    'csrf_validate', 'csrf_check_token', 'csrf_id_value', 'auth_csrf', 'csrf_token_form', 'csrf_session_id', 
    'csrf_secret_token', 'form_csrf_key', 'token_test', 'validate_csrf', 'auth_csrf_token123', 'secure_csrf_token', 
    'csrf_verification', 'csrf_data_token', 'csrf_key_value', 'csrf_verify_code', 'csrf_session_key', 
    'csrf_secure_code', 'csrf_form_value', 'form_token', 'csrf_key123', 'csrf_session_value', 'validate_csrf_code', 
    'token_form', 'csrf_validation_key', 'csrf_test_token', 'token_verification', 'csrf_test_key', 
    'csrf_validate_token', 'csrf_form_code', 'csrf_session_code', 'csrf_security_code', 'secure_csrf', 
    'csrf_form_secret', 'csrf_security_value', 'csrf_key1234', 'csrf_secret_code', 'csrf_code_test', 
    'csrf_validation_id', 'csrf_code_key', 'form_csrf_value', 'csrf_id123', 'csrf_token_1234', 'csrf_session_test', 
    'csrf_code_id', 'csrf_key_test', 'csrf_data_value', 'csrf_form_check', 'csrf_form_token123', 'csrf_secure_value', 
    'csrf_code1234', 'csrf_id_secret', 'csrf_test_value', 'csrf_id_key', 'csrf_form_auth', 'csrf_session_secret', 
    'csrf_token_verify', 'token_security', 'form_csrf_id', 'csrf_secure_id', 'csrf_session_code123', 'csrf_secret_key', 
    'csrf_verify_id', 'csrf_check_key', 'csrf_code_validate', 'csrf_id_code', 'csrf_test_code', 'csrf_validation_secret', 
    'csrf_key_test123', 'csrf_code_form', 'csrf_token_security', 'csrf_session_key123', 'csrf_form_secret123', 
    'csrf_verification_token', 'csrf_form_test', 'csrf_id_value123', 'csrf_security_test', 'csrf_data_secret', 
    'csrf_check_code', 'csrf_id_form', 'csrf_token_data', 'csrf_secret_id', 'csrf_token_secret', 'csrf_session_form', 
    'csrf_verify_code', 'csrf_security_id', 'csrf_id_token123', 'csrf_token_id', 'csrf_code_key123', 'csrf_session_verify', 
    'csrf_form_code123', 'csrf_code_form123', 'csrf_test_id', 'csrf_form_validate', 'csrf_token_code', 'csrf_data_key', 
    'csrf_form_verify', 'csrf_secret_test', 'csrf_key_value123', 'csrf_token_validate', 'csrf_form_key123', 
    'csrf_id_secure', 'csrf_session_validation', 'csrf_form_check123', 'csrf_key_validate', 'csrf_security_form', 
    'csrf_code_security', 'csrf_verify_token123', 'csrf_id_form123', 'csrf_session_verification', 'csrf_key_secret', 
    'csrf_token_data123', 'csrf_data_code', 'csrf_session_form123', 'csrf_form_security', 'csrf_code_verify', 
    'csrf_session_key_test', 'csrf_key_validate123', 'csrf_security_validate', 'csrf_token_key123', 'csrf_id_code123', 
    'csrf_form_security123', 'csrf_data_form', 'csrf_verify_secret', 'csrf_session_code_verify', 'csrf_form_security_key', 
    'csrf_code_key_test', 'csrf_token_form123', 'csrf_secure_verify', 'csrf_session_data', 'csrf_key_secret123', 
    'csrf_id_check', 'csrf_token_code', 'csrf_form_data', 'csrf_session_key_validate', 'csrf_security_secret', 
    'csrf_verify_form', 'csrf_code_data', 'csrf_session_key_code', 'csrf_id_form_verify', 'csrf_token_form1234', 
    'csrf_code_form_key', 'csrf_security_token123', 'csrf_session_key_form', 'csrf_verify_code123', 'csrf_key_test1234', 
    'csrf_token_form_test', 'csrf_id_secret123', 'csrf_form_check1234', 'csrf_session_key_security', 'csrf_security_verify', 
    'csrf_code_data123', 'csrf_token_form_verify', 'csrf_session_form_key', 'csrf_key_code', 'csrf_id_form_code', 
    'csrf_token_form_key', 'csrf_data_test', 'csrf_session_key_verify', 'csrf_code_secret', 'csrf_verify_key', 'csrf_token_check', 
    'csrf_id_verify', 'csrf_form_id123', 'csrf_security_form123', 'csrf_session_id_secret', 'csrf_key_form', 'csrf_token_key_test', 
    'csrf_code_security123', 'csrf_secret_verify', 'csrf_id_data', 'csrf_session_form_code', 'csrf_token_key_value', 'csrf_code_session', 
    'csrf_form_id_verify', 'csrf_session_key_security', 'csrf_data_id', 'csrf_security_key123', 'csrf_token_code1234', 'csrf_id_session', 
    'csrf_form_key_verify', 'csrf_session_token_secret', 'csrf_key_session', 'csrf_token_id123', 'csrf_code_verify123', 'csrf_form_session', 
    'csrf_security_key_test', 'csrf_id_form1234', 'csrf_token_id_secret', 'csrf_code_key_value', 'csrf_session_verify123', 'csrf_form_key_test', 
    'csrf_secret_session', 'csrf_token_session', 'csrf_id_key1234', 'csrf_code_verify_key', 'csrf_form_token_secret', 'csrf_session_code1234', 
    'csrf_key_verify', 'csrf_token_secure', 'csrf_id_key_value', 'csrf_code_test123', 'csrf_session_form_verify', 'csrf_form_key_secret', 
    'csrf_security_code123', 'csrf_id_token_test', 'csrf_token_form_key123', 'csrf_code_session123', 'csrf_session_key1234', 'csrf_form_verify_key', 
    'csrf_key_code', 'csrf_id_code_test', 'csrf_token_id_verify', 'csrf_code_secret123', 'csrf_form_key_code', 'csrf_security_form_key', 
    'csrf_id_key_verify', 'csrf_token_key_code', 'csrf_session_secret123', 'csrf_code_key1234', 'csrf_form_session', 'csrf_security_verify'
]

def scan_with_csrf_payloads(target_url, csrf_payloads):
    try:
        for payload in csrf_payloads:
            # Craft the malicious request with the CSRF payload
            malicious_request = {
                'method': 'POST',  # HTTP method (e.g., POST)
                'url': target_url,  # Target URL
                'data': {  # Payload data (e.g., form fields)
                    'username': 'attacker',
                    'password': 'password123',
                    'csrf_token': payload  # CSRF payload
                },
                'headers': {  # Headers (if needed)
                    'User-Agent': 'Mozilla/5.0',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    # Add more headers as needed
                }
            }

            # Send the malicious request
            response = requests.request(**malicious_request)

            # Check the response to detect potential CSRF vulnerabilities
            if 'CSRF token invalid' in response.text or 'CSRF token missing' in response.text:
                print(f"CSRF vulnerability detected with payload: {payload}")
                print(f"Response content:\n{response.text}")
            else:
                print(f"No CSRF vulnerability detected with payload: {payload}")

    except requests.RequestException as e:
        print(f"Error during request: {e}")

if __name__ == "__main__":
    # Example usage:
    target_url = input("Enter Websit : ")
    print ("\033[31m") 
    # Perform CSRF scan with specified payloads
    scan_with_csrf_payloads(target_url, csrf_payloads)
