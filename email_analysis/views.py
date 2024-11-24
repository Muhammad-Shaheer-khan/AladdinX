from django.views.generic import TemplateView
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import re, email, json, requests, time, datetime, mimetypes
from email import policy


class IndexView(TemplateView):
    template_name = 'index.html'

# APIs
def api(index):
    api_lst = {'ipgeolocation':'Enter_Your_API', 'virusTotal': 'Enter_Your_API', "gemini":'Enter_Your_API'}
    return api_lst[index]

    # ip Geolocation

def get_public_ip(ip, retries=7, backoff_factor=2):
    attempt = 0
    api_key = api('ipgeolocation')

    while attempt < retries:
        try:
            ip_info_url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}"
            response = requests.get(ip_info_url, timeout=10)
            print('*' * 10)
            print(f"Your public IP address is: {ip}")

            if response.status_code == 200:
                data = response.json()
                relevant_fields = {
                    'region': data.get('state_prov', 'Not Available'),
                    'country': data.get('country_name', 'Not Available'),
                    'country_code': data.get('country_code2', 'Not Available'),
                    'country_code_iso3': data.get('country_code3', 'Not Available'),
                    'flag': data.get('country_flag', 'Not Available'),
                    'country_capital': data.get('country_capital', 'Not Available'),
                    'continent_code': data.get('continent_code', 'Not Available'),
                    'district': data.get('district', 'Not Available'),
                    'latitude': data.get('latitude', 'Not Available'),
                    'zipcode': data.get('zipcode', 'Not Available'),
                    'longitude': data.get('longitude', 'Not Available'),
                    'timezone': data.get('time_zone', {}).get('name', 'Not Available'),
                    'utc_offset': data.get('time_zone', {}).get('offset', 'Not Available'),
                    'currency': data.get('currency', {}).get('code', 'Not Available'),
                    'currency_name': data.get('currency', {}).get('name', 'Not Available'),
                    'currency_symbol': data.get('currency', {}).get('symbol', 'Not Available'),
                    'languages': data.get('languages', 'Not Available'),
                    'isp': data.get('isp', 'Not Available'),
                    'organization': data.get('organization', 'Not Available'),
                    'asn': data.get('asn', 'Not Available'),
                }
                return relevant_fields
            elif response.status_code == 429:
                print("Rate limit exceeded. Retrying...")
                time.sleep(backoff_factor ** attempt)
                attempt += 1
            else:
                print(f"Failed to retrieve details. Status code: {response.status_code}")
                print("Response content:", response.text)
                return None

        except requests.exceptions.RequestException as e:
            print(f"Failed to retrieve public IP address: {e}")
            attempt += 1
            time.sleep(backoff_factor ** attempt)

    print("Exceeded maximum retry attempts.")
    return None

def extract_ip(header_value):
    # Pattern to match both IPv4 and IPv6 addresses
    ip_pattern = r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b)'
    match = re.search(ip_pattern, header_value)
    return match.group(1) if match else None

    # VirusTotal

def ip_analysis(num, IoC):   
    if num == 'ip':
        ip = IoC
        api_key = api('virusTotal')
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            'x-apikey': api_key
        }

        max_retries = 5  # Maximum number of retries
        retry_delay = 2  # Delay between retries in seconds

        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=27)
                print(response.status_code)
                if response.status_code == 200:
                    data = response.json()

                    graph_Details = {
                        'harmless': data['data']['attributes']['last_analysis_stats'].get('harmless'),
                        'undetected': data['data']['attributes']['last_analysis_stats'].get('undetected'),
                        'suspicious': data['data']['attributes']['last_analysis_stats'].get('suspicious'),
                        'malicious': data['data']['attributes']['last_analysis_stats'].get('malicious'),
                        'reputation': data['data']['attributes'].get('reputation'),
                        'sum': (
                            data['data']['attributes']['last_analysis_stats'].get('harmless', 0) +
                            data['data']['attributes']['last_analysis_stats'].get('undetected', 0) +
                            data['data']['attributes']['last_analysis_stats'].get('suspicious', 0) +
                            data['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                        )
                    }
                    print("vt details",graph_Details)

                    # Check if any key values are None or empty
                    if all(value is not None for value in graph_Details.values()):
                        relevant_fields = {
                            'IP Address': data['data']['id'],
                            'Categories': data['data']['attributes'].get('categories', 'Not Available'),
                            'Last Analysis Date': data['data']['attributes'].get('last_analysis_date', 'Not Available'),
                            'Tags': data['data']['attributes'].get('tags', 'Not Available'),
                            'First Seen': data['data']['attributes'].get('first_seen', 'Not Available'),
                            'Network Information': data['data']['attributes'].get('network', 'Not Available'),
                            'Hostnames': data['data']['attributes'].get('hostnames', 'Not Available'),
                        }

                        # print("date:", relevant_fields['Last Analysis Date'])
                        if isinstance(relevant_fields['Last Analysis Date'], int):
                            relevant_fields['Last Analysis Date'] = datetime.datetime.fromtimestamp(relevant_fields['Last Analysis Date']).strftime("%Y-%m-%d %H:%M:%S")

                        return relevant_fields, graph_Details
                    else:
                        print(f"Some fields are missing in the response for IP: {ip}. Retrying...")

                else:
                    print(f"Failed to retrieve analysis for IP: {ip}. Status code: {response.status_code}")
                    return {}, {}  # Return empty dictionaries if the response is not successful

            except requests.exceptions.ConnectTimeout:
                print(f"Connection timed out for IP: {ip}")
                return {"Notification":"Enable to retrieve data, please Boom again..."}, {}  # Return empty dictionaries in case of a timeout

            time.sleep(retry_delay)  # Wait before retrying

        print(f"Max retries reached. Could not retrieve complete analysis for IP: {ip}")
        return {}, {}  # Return empty dictionaries after max retries
    else:
        return "No other option added yet xd."
                    
# identify links
def parse_input(input_text):
    # Use a regex pattern to match valid URLs
    url_pattern = r'https?://[^\s<>"\'=]+'
    
    # Find all matches in the input text
    links = re.findall(url_pattern, input_text)
    
    # Clean up any unwanted trailing characters that may follow the URL
    links = [link.rstrip('=') for link in links]  # Remove any trailing '='

    sandbox_url_format = "https://www.browserling.com/browse/win10/chrome127/{}"
    sandboxed_links = []
    for link in links:
        sandboxed_link = sandbox_url_format.format(link)
        sandboxed_links.append(sandboxed_link)
    return sandboxed_links


# Attachment analysis

def attachment_analysis(header):
    suspicious_files = {}

    # Define file types and their associated categories
    attachment_types = {
        'Microsoft Office': ['docx', 'doc', 'pptx', 'ppt', 'xlsx', 'xls'],
        'Adobe': ['pdf', 'ai', 'psd'],
        'Open Office': ['odt', 'ods', 'odp'],
        'Executable files': ['exe', 'app', 'bin'],
        'Script files': ['js', 'vbs', 'bat'],
        'Compressed files': ['zip', 'rar', '7z'],
        'Macro-enabled documents': ['docm', 'xlsm', 'pptm'],
        'Phishing Attachments': ['docx', 'doc', 'pptx', 'ppt', 'xlsx', 'xls', 'pdf'],
        'Text Formats': ['txt', 'rtf'],
        'Image Formats': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'ai', 'eps'],
        'Audio Formats': ['mp3', 'wav', 'aac', 'flac'],
        'Video Formats': ['mp4', 'mov', 'avi', 'mkv', 'wmv'],
        'Other Formats': ['tar', 'gz', 'bz2']
    }

    # Iterate through each part of the email header
    for part in header.walk():
        # Skip multipart containers
        if part.get_content_maintype() == 'multipart':
            continue

        # Skip parts without 'Content-Disposition' header
        if part.get('Content-Disposition') is None:
            continue

        # Process attachments
        filename = part.get_filename()
        if filename:
            file_type, _ = mimetypes.guess_type(filename)
            if file_type:
                file_extension = file_type.split('/')[-1]
                for category, extensions in attachment_types.items():
                    if file_extension in extensions:
                        suspicious_files[filename] = {'category': category}
                        break

    suspicious_links = parse_input(header.as_string())
    return suspicious_files, suspicious_links

@csrf_exempt
def analyze_header(request):
    email_header_words = [
        "From", "To", "Date", "Subject", "Message-ID", "MIME-Version", "Content-Type"
    ]

    if request.method == 'POST':
        body = json.loads(request.body)
        email_header = body.get('header', '')
        email_message = email.message_from_string(email_header)

        if all(word in email_message for word in email_header_words):
            parsed_header = {key: value for key, value in email_message.items()}

            spf_header = email_message.get('Received-SPF', '')
            ip_address = extract_ip(spf_header)

            if not ip_address:
                received_headers = email_message.get_all('Received', [])
                for header in received_headers:
                    ip_address = extract_ip(header)
                    if ip_address:
                        break

            print(f"Extracted IP: {ip_address}")

            retry_count = 0
            max_retries = 3

            while retry_count < max_retries:
                try:
                    vt_details, graph_details = ip_analysis('ip' ,ip_address)
                    break  # Break the loop if successful
                except ValueError:
                    retry_count += 1
                    print(f"Retrying... Attempt {retry_count}/{max_retries}")
                    time.sleep(1)  # Short delay before retrying

            if retry_count == max_retries:
                return JsonResponse({'error': 'Failed to retrieve analysis after multiple attempts'}, status=500)

            ipapi_details = get_public_ip(ip_address) or {}

            IP_results = {
                'VirusTotal': vt_details,
                'IPAPI': ipapi_details
            }

            # Attachments_analysis triger
            suspicious_files, suspicious_links = attachment_analysis(email_message)
            
            attachments_result = {}  # Define an empty dictionary

            if suspicious_files or suspicious_links:
                attachments_result = {
                    'suspicious_files': suspicious_files,
                    'suspicious_links': suspicious_links
                }

            result_details = extract_result_fields(email_message)
            compare_email = compare_emails((result_details["sender email"], result_details["return_path"]))
            compare_email_dict = {"email match": compare_email[0], "sendDomain":compare_email[1], "returnDomain":compare_email[2]}
            
            spf_info = extract_spf_info(email_header)
            SPF_Response = spf_checking(spf_info["Received-SPF"])
            if len(SPF_Response) == 1:
                SPF_Response['Bounce Section'] = "Unavailable"
                SPF_Response['Sign Analysis'] = "Unavailable"
            
            dkim_info = extract_dkim_info(email_header)
            dkimResult = {}
            dkimResult[dkim_info["Authentication-Results (DKIM result)"]] = analyze_dkim_signature(dkim_info["Signature"], dkim_info["Authentication-Results (DKIM result)"])
                        
            # spam details check
            spam_fields = check_spam_details(email_header)

            mxRecord = analyze_mx_headers(email_header)
           
            dmarcRecord = parse_dmarc_header(email_header)
            
            SuspiciousWords = suspicious_words_check(email_header)
            
            subject, body = content_extraction(0, email_header)
            prompt = f"Email subject is: {subject} and its body is {body}"
            ai_respose = Ai_Response(prompt)
            
            return JsonResponse({'result': parsed_header, 'analysis': IP_results, 'graph_details': graph_details, 'attachments_result': attachments_result, "mail_match":compare_email_dict, "spf":SPF_Response, "dkim":dkimResult, "spamField":spam_fields, "mxRecord":mxRecord, "dmarcRecord":dmarcRecord, "SuspiciousWords":SuspiciousWords, "aiRespose":ai_respose})
        else:
            return JsonResponse({'error': 'Invalid email header format'}, status=400)

def extract_spf_info(email_header):
    # Pattern to extract the required fields
    received_spf_pattern = re.compile(r'^Received-SPF:\s*(.*)$', re.MULTILINE)
    
    # Extracting the information
    extracted_info = {}
    match = received_spf_pattern.search(email_header)
    
    if match:
        extracted_info['Received-SPF'] = match.group(1)
    
    return extracted_info

def spf_checking(spf_info):
    # Initialize the output dictionary
    output = {}

    # Check for SPF result
    if "pass" in spf_info:
        output['SPF Status'] = 'Pass'
    elif "softfail" in spf_info:
        output['SPF Status'] = 'Softfail'
    elif "fail" in spf_info:
        output['SPF Status'] = 'Fail'
    else:
        output['SPF Status'] = 'Unknown'

    # Extract the bounce section
    bounce_section_match = re.search(r'domain of ([^ ]+)', spf_info)
    if bounce_section_match:
        bounce_email = bounce_section_match.group(1)
        # Extract only the part after the '@'
        bounce_domain = bounce_email.split('@')[1]
        output['Bounce Section'] = bounce_domain

        # Analyze special characters in the bounce email
        special_signs = analyze_bounce_email(bounce_email)
        output['Sign Analysis'] = special_signs

    return output

def analyze_bounce_email(bounce_email):
    # Initialize a list to hold the analyses
    analyses = []

    # Check for special characters and their meanings
    if '+' in bounce_email:
        analyses.append('Bulk Email or Aliasing')  # Indicates potential bulk email or aliasing
    if '-' in bounce_email:
        analyses.append('Commonly used in names or organizations')  # Commonly used in names or organizations
    if '.' in bounce_email.split('@')[0]:  # Check only the local part
        analyses.append('Could be legitimate name')  # Could indicate a legitimate name or separation
    if 'bounce' in bounce_email:
        analyses.append('Bounce address')  # Indicates a bounce address

    # If no special signs are found, return 'None'
    return analyses

def compare_emails(email_tuple):
    sender, return_path = email_tuple
    # Extract domain and strip any unwanted characters like '>' at the end
    sender_domain = re.search(r'@([\w.-]+)', sender).group(1).strip('>')
    return_path_domain = re.search(r'@([\w.-]+)', return_path).group(1).strip('>')
    # Return comparison and the cleaned domains
    return (sender_domain == return_path_domain, sender_domain, return_path_domain) 

# Computing result here      
def extract_result_fields(email_message):
    sender_email = email_message['From']
    return_path = email_message['Return-Path']   
    result_dict = {"sender email":sender_email, "return_path": return_path}
    return result_dict

def extract_dkim_info(email_header):

    dkim_info = {}

    # DKIM-Signature
    dkim_signature = re.search(r'DKIM-Signature:\s*(.+)', email_header, re.IGNORECASE)
    if dkim_signature:
        dkim_info['Signature'] = dkim_signature.group(1).strip()

    # Authentication-Results (DKIM result)
    auth_results = re.search(r'Authentication-Results:\s*[\w\-\.]+;\s*dkim=([\w\s]+)', email_header, re.IGNORECASE)

    if auth_results:
      # Extract first word of authentication result
      match = re.search(r'\b\w+\b', auth_results.group(1))
      dkim_info['Authentication-Results (DKIM result)'] = match.group(0)

    if not(dkim_info):
        
        ARC_Message_Signature = r"ARC-Message-Signature:\s*(.*?)(?=\n\S|$)"
        match = re.search(ARC_Message_Signature, email_header, re.MULTILINE)
        if match:
            dkim_info["Signature"] = match.group(0).strip()
            dkim_info['Authentication-Results (DKIM result)'] = "Not Defined"

    return dkim_info

def analyze_dkim_signature(dkim_signature, valueDKIM):
    # Initialize a dictionary to hold the parsed parameters
    dkim_info = {}
               
    # Split the signature into individual parameters and strip whitespace
    parameters = [param.strip() for param in dkim_signature.split(';') if param.strip()]

    # Define possible meanings for each parameter
    meanings = {
        'v': 'DKIM version 1.',
        'a': 'Signing algorithm used.',
        'c': 'Canonicalization method used.',
        'd': 'Domain of the signing entity.',
        's': 'Selector for the public key.',
        'bh': 'Body hash for integrity check.',
        'b': 'The actual cryptographic signature.',
        't': 'Timestamp of signature creation.',
        'x': 'Expiration time of the signature.',
        'i': 'Identity of the signer.'
    }

    # Process each parameter
    for param in parameters:
        # Split into key and value at the first '=' occurrence
        key_value = param.split('=', 1)
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()
            if key == 't' or key == 'x':  # Convert timestamps to readable format
                try:
                    try:
                        readable_time = datetime.datetime.utcfromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    except ValueError:
                        readable_time = value 
                    dkim_info[key] = readable_time
                except ValueError:
                    dkim_info[key] = value  # If conversion fails, keep the original value
            elif key in meanings:
                dkim_info[key] = value

    # Initialize the final interpretation dictionary
    dkim_interpretation = {}

    # Interpret values and store in dkim_interpretation
    for key, value in dkim_info.items():
        if key == 'a':  # Signing algorithm interpretation
            if value == 'rsa-sha256':
                dkim_interpretation[value] = 'RSA signature with SHA-256 hashing (most commonly used).'
            elif value == 'rsa-sha1':
                dkim_interpretation[value] = 'RSA signature with SHA-1 hashing (less secure, older standard).'
            elif value == 'ed25519':
                dkim_interpretation[value] = 'Ed25519 algorithm (used in newer implementations for better security).'
            else:
                dkim_interpretation[value] = 'Unknown or custom algorithm.'
        
        elif key == 'c':  # Canonicalization method interpretation
            if value == 'relaxed/relaxed':
                dkim_interpretation[value] = 'Both header and body are canonicalized using the "relaxed" method.'
            elif value == 'relaxed/simple':
                dkim_interpretation[value] = 'Header is canonicalized with "relaxed", body with "simple".'
            elif value == 'simple/relaxed':
                dkim_interpretation[value] = 'Header is canonicalized with "simple", body with "relaxed".'
            elif value == 'simple/simple':
                dkim_interpretation[value] = 'Both header and body are canonicalized using the "simple" method.'
            else:
                dkim_interpretation[value] = 'Unknown or custom canonicalization method.'

        elif key == 'd':  # Domain interpretation
            dkim_interpretation[value] = f'Valid domain name: {value}.'

        elif key == 'bh':  # Body hash interpretation
            dkim_interpretation[value] = 'Body hash is provided for integrity check.'

        elif key == 'b':  # Signature interpretation
            dkim_interpretation[value] = 'Base64-encoded signature, used to verify email integrity and authenticity.'

        else:  # General interpretation for other keys
            dkim_interpretation[value] = meanings.get(key, 'Unknown meaning')

    dkim_interpretation = {value: key for key, value in dkim_interpretation.items()}
    dkim_interpretation.update({"Authentication-Results" : valueDKIM})
    return dkim_interpretation

def check_spam_details(email_header):
    # Initialize a dictionary to hold spam details
    spam_details = {'spam_detail': 'not found'}

    # Split the email into lines
    lines = email_header.splitlines()

    # Check for spam-related fields
    for line in lines:
        if line.startswith("X-Spam-Flag:"):
            spam_details['X-Spam-Flag'] = line.split(":", 1)[1].strip()
            spam_details['X-Spam-Flag Interpretation'] = "Indicates whether the email is flagged as spam (YES/NO)."
            spam_details['spam_detail'] = 'found'  # Update to found if spam flag is present
            
        elif line.startswith("X-Spam-Score:"):
            spam_score = line.split(":", 1)[1].strip()
            spam_details['X-Spam-Score'] = spam_score
            
            # Interpretation based on the spam score value
            try:
                score_value = float(spam_score)
                if score_value < 0:
                    spam_details['X-Spam-Score Interpretation'] = "Negative score indicates a lower likelihood of being spam."
                elif score_value == 0:
                    spam_details['X-Spam-Score Interpretation'] = "A score of zero indicates a neutral evaluation, not marked as spam."
                else:
                    spam_details['X-Spam-Score Interpretation'] = "Positive score indicates a higher likelihood of being spam."
            except ValueError:
                spam_details['X-Spam-Score Interpretation'] = "Invalid score format."
                
            spam_details['spam_detail'] = 'found'  # Update to found if spam score is present

    # Check if any spam details were found
    if spam_details['spam_detail'] == 'not found':
        spam_details['X-Spam-Flag'] = "N/A"
        spam_details['X-Spam-Flag Interpretation'] = "N/A"
        spam_details['X-Spam-Score'] = "N/A"
        spam_details['X-Spam-Score Interpretation'] = "N/A"
        return spam_details
    
    return spam_details

def analyze_mx_headers(email_header):
    """
    Analyze MX-related fields in the email header and return a dictionary with details and interpretations.
    """
    mx_info = {}
    mx_interpretation = {}

    # Define regex patterns for MX fields
    mx_record_pattern = re.compile(r"^Received:.*by\s+([\w.-]+)\s+\(.*\).*;\s+(.*)", re.MULTILINE | re.IGNORECASE)
    from_domain_pattern = re.compile(r"^From:\s+.*@([\w.-]+)", re.MULTILINE | re.IGNORECASE)
    mx_route_pattern = re.compile(r"^Received:\s+from\s+([\w.-]+)\s+\(.*\)\s+by\s+([\w.-]+)\s+with\s+(\w+)", re.MULTILINE | re.IGNORECASE)

    # Extract MX fields
    mx_records = mx_record_pattern.findall(email_header)
    from_domains = from_domain_pattern.findall(email_header)
    mx_routes = mx_route_pattern.findall(email_header)

    # Store and interpret MX records
    if mx_records:
        mx_info['mx_records'] = mx_records
        mx_interpretation['mx_records'] = "MX servers that handled the email. These represent the mail servers involved in receiving the email."
    
    # Store and interpret 'From' domain
    if from_domains:
        mx_info['from_domains'] = from_domains
        mx_interpretation['from_domains'] = "Domains from which the email was sent."
    
    # Store and interpret MX routes
    if mx_routes:
        mx_info['mx_routes'] = mx_routes
        mx_interpretation['mx_routes'] = "Routes through which the email passed, showing the sequence of mail servers."

    # Combine both info and interpretations
    mx_details = {"Mail Exchange Detail": "found" if mx_info else "not found"}
    for key in mx_info:
        # print(mx_info[key])
        mx_details[key] = [mx_info[key], mx_interpretation[key]]
    # mx_details = {"Mail Exchange Setails":{mx_info[key]: mx_interpretation[key]} for key in mx_info}



    return mx_details

def parse_dmarc_header(email_header):
    dmarc_data = {}
    
    # Try to find DMARC result in the header
    dmarc_match = re.search(r'dmarc=(\w+)', email_header, re.IGNORECASE)
    
    if not dmarc_match:
        # If no DMARC result is found, return with a message
        return {"DMARC Result": "No DMARC data found"}
    
    # Extract the DMARC result (pass/fail/none)
    dmarc_result = dmarc_match.group(1).lower()
    if dmarc_result not in ['pass', 'fail', 'none']:
        dmarc_result = "Unknown"
    dmarc_data["DMARC Result"] = dmarc_result
    
    # Define a list of DMARC parameters that may appear in the header
    dmarc_params = {
        "p": "Policy",               # Policy for the main domain
        "sp": "Subdomain Policy",     # Policy for subdomains
        "dis": "Disposition",         # Disposition for email
        "pct": "Percentage",          # Percentage of emails the DMARC policy applies to
        "fo": "Failure Reporting",    # Forensic reporting options
        "rf": "Report Format",        # Format for reports (e.g., AFRF)
        "ri": "Report Interval",      # Interval in seconds between reports
        "rua": "Aggregate Report URI",# URI for aggregate reports
        "ruf": "Forensic Report URI", # URI for forensic reports
        "aspf": "Alignment Mode (SPF)",# SPF alignment mode
        "adkim": "Alignment Mode (DKIM)", # DKIM alignment mode
    }

    # Define explanations for each parameter in simple terms
    explanations = {
        "none": "No restrictions, emails go through normally.",
        "quarantine": "Emails are marked as suspicious and may go to spam.",
        "reject": "Emails are fully blocked from reaching the inbox.",
        "0": "No forensic reports will be sent.",
        "1": "Forensic reports will be sent when an authentication failure occurs.",
        "afrf": "Aggregate reports are sent in 'Aggregate Feedback Report Format'.",
        "rfc5322": "The report format follows the 'Internet Message Format' (RFC 5322).",
        "s": "Strict alignment is enforced.",
        "r": "Relaxed alignment is allowed.",
    }

    # Check for each possible DMARC parameter and add it to the dictionary with actual values as keys
    for param, _ in dmarc_params.items():
        param_match = re.search(fr'{param}=([\w\-]+)', email_header, re.IGNORECASE)
        if param_match:
            value = param_match.group(1).upper()
            explanation = explanations.get(value.lower(), f"Unknown value: {value}")
            dmarc_data[f'{param}={value}'] = explanation

    return dmarc_data

def content_extraction(restricted ,email_header):
    email_message = email.message_from_string(email_header, policy=policy.default)
    subject = email_message['subject']
    body = ""
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if content_type == "text/plain" and disposition is None:
                body = part.get_payload(decode=True).decode(part.get_content_charset(), errors='replace')
                break
            elif content_type == "text/html" and disposition is None:
                body = part.get_payload(decode=True).decode(part.get_content_charset(), errors='replace')
    else:
        body = email_message.get_payload(decode=True).decode(email_message.get_content_charset(), errors='replace')
        
    if not restricted:
        return subject, body
    else:
        subject_words = subject.split() if subject else []
        body_words = body.split() if body else []

        return {"content_in_list": subject_words+body_words}

def suspicious_words_check(email_header):
    
    with open("email_analysis\Files\listSpamWord.txt", "r") as file:
        line = file.read()
    suspicious_words = (eval(line))
    
    body = content_extraction( 1, email_header)
    checkable_list = body["content_in_list"]
    found_simillar = 0
    for word in suspicious_words:
        for checkable_word in checkable_list:
            if word.lower() == checkable_word.lower():
                # print(word, checkable_word)

                found_simillar += 1
                break
    return({"Suspicious words percentage": str(round((found_simillar/len(checkable_list))*100))+"%"})

# AI suggestions
def Ai_Response(body):
    API_KEY = api("gemini")
    url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent'

    # Set up the headers and data
    headers = {
        'Content-Type': 'application/json'
    }
    
    data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"""{body}' Please respond in this format: Email: (Spam/Not spam/Suspicious/May be attack/Normal), Reason: short (3 lines) corresponding to the email, Suggestion: short (3 lines) corresponding to the email what to do for my layman. Must give all headings (Email section, Reason section, and Suggestion section) in response without change the next line"""
                    }
                ]
            }
        ]
    }

    def get_ai_response():
        while True:
            # Make the POST request
            response = requests.post(f"{url}?key={API_KEY}", headers=headers, data=json.dumps(data))
    
            # Check if the request was successful
            if response.status_code == 200:
                result = response.json()
    
                # Check if 'candidates' is present and not empty
                if result and 'candidates' in result and result['candidates']:
                    return result  # Return the result if valid response is received
    
            # Wait for a short period before retrying
            time.sleep(1)

    response = ""
    # Get the response
    result = get_ai_response()

    # Extracting relevant information
    candidates = result.get('candidates', [])

    for candidate in candidates:
        content = candidate.get('content', {}).get('parts', [{}])[0].get('text', 'No content found')
        clean_content = content.replace('*', '').strip()  # Clean asterisks

        # Remove any leading symbols from each line in clean_content
        cleaned_lines = []
        for line in clean_content.splitlines():
            cleaned_line = line.lstrip(' *-#@')  # Add any symbols you want to remove here
            cleaned_lines.append(cleaned_line)

        # Join the cleaned lines back into a single string
        clean_content = "\n".join(cleaned_lines)

        result_dict = {
            "email": None,
            "reason": None,
            "suggestion": None
        }
        # Initialize variables to capture multi-line content
        current_key = None
        buffer = []

        # Extract email, reason, and suggestion from the cleaned content
        if clean_content:
            lines = clean_content.splitlines()
            for line in lines:
                clean_line = line.lower().strip()
                # Check if the line starts with a new section header
                if clean_line.startswith("email:"):
                    if current_key and buffer:
                        result_dict[current_key] = ' '.join(buffer).strip()
                    current_key = "email"
                    buffer = [clean_line.split(":", 1)[1].strip()]  # Start the buffer with the current line's value
                    
                elif clean_line.startswith("reason:"):
                    if current_key and buffer:
                        result_dict[current_key] = ' '.join(buffer).strip()
                    current_key = "reason"
                    buffer = [clean_line.split(":", 1)[1].strip()]  # Start the buffer with the current line's value
                elif clean_line.startswith("suggestion:"):
                    if current_key and buffer:
                        result_dict[current_key] = ' '.join(buffer).strip()
                    current_key = "suggestion"
                    buffer = [clean_line.split(":", 1)[1].strip()]  # Start the buffer with the current line's value
                else:
                    # If the line doesn't start with a new key, add it to the buffer if it's not empty
                    if current_key and clean_line:
                        buffer.append(clean_line)

            if current_key and buffer:
                result_dict[current_key] = ' '.join(buffer).strip()
                # Clean and capitalize the email
                temp = result_dict["email"].split()
                if len(result_dict["email"]) > 0:
                    result_dict["email"] = temp[0]
                    if result_dict["email"] == "not":
                        result_dict["email"] = temp[0]+" "+temp[1]

                # Capitalize the first letter of each value
                for key, value in result_dict.items():
                    result_dict[key] = value.capitalize()

        return result_dict

    else:
        print("Error:", response.status_code, response.text)
