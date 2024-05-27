import requests
import time
import json
import base64

from modules import validation, whois_lookup_ipwhois, utils


class VirusTotal:
    # API data
    FREE = 15 # 15 sec delay between requests for free Virus Total subscription
    PREMIUM = 60/300 # Virus Total allows 300 entire group for premium subscription (max speed)
    # Analyze time
    URL_ANALIZE_TIME = 10
    
    def __init__(self, vt_api_key: str) -> None:
        if not validation.Validation.validate_vt_api_key(vt_api_key):
            raise ValueError(f"Wrong API key format. Key {vt_api_key} is not valid")
        
        self.vt_api_key = vt_api_key

    # Main Whois fields parsed from VT json request
    MAIN_IP_WHOIS_FIELDS = {
        # Showed in short report
        'Country':'country',
        'City': None,
        'Organization':'descr',
        'NetName':'netname',
        'CIDR':None,
        'Updated':'last-modified',
        # The rest is written to the report
        'NetRange':'inetnum',
        'Address' : 'address',
        'OrgAbusePhone':'phone',
        'OrgAbuseEmail':'abuse-mailbox'
        }

    MAIN_DOMAIN_WHOIS_FIELDS = {
        # Showed in short report
        'Country':'Admin Country',
        'City': 'Admin City',
        'Organization':'Admin Organization',
        'NetName':None,
        'CIDR':None,
        'Updated':'Updated Date',
        # The rest is written to the report
        'NetRange':None,
        'Address' : 'Province',
        'OrgAbusePhone':'Registrar Abuse Contact Phone',
        'OrgAbuseEmail':'Admin Email'
        }

    # VT score from json request needed for analyzing 
    MAIN_VT_FIELDS = [
            'harmless_score',
            'malicious_score',
            'suspicious_score',
            'undetected_score'
        ]

    # V3 API methods
    def parse_full_whois_vt_info(self,whois_info: str):
        whois_fields = whois_info.split('\n')    
        result = {}
        
        for field in whois_fields:
            tmp = field.split(':',1)
            field_name = tmp[0].strip()
            
            if not field_name:
                continue
            
            if len(tmp) > 1:
                field_value = tmp[1].strip()
    
                if not field_value:
                    continue
                    
                result.update({field_name:field_value})
            else:
                result.update({field_name:None})
                
        return result

    def parse_main_whois_vt_info(self,whois_info: str, whois_main_fields=MAIN_IP_WHOIS_FIELDS):
        whois_info = whois_info.split('\n')
        whois_info = [record.split(':') for record in whois_info]
        
        result = {}
        
        for field in whois_main_fields:
            result.update({field:''})
            for record in whois_info:
                if field == record[0].strip():
                    result.update({field:record[1]})
            
                if result[field] == '':
                    for tmp_record in whois_info:
                        if whois_main_fields[field] == tmp_record[0]:
                            result[field] = tmp_record[1]        
        
        return result

    def virus_total_info_check(self,ioc: str, full_info = True):
        headers = {"x-apikey": self.vt_api_key}
        
        # Fields depending on type of IOC
        url = None
        whois_main_fields = None
        ioc_type = None
          
        if validation.Validation.validate_ip(ioc):
            print(f'{ioc} recognized as IP address')
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            whois_main_fields = VirusTotal.MAIN_IP_WHOIS_FIELDS
            ioc_type = 'IP'
        elif validation.Validation.validate_domain(ioc):
            print(f'{ioc} recognized as domain name')
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            whois_main_fields = VirusTotal.MAIN_DOMAIN_WHOIS_FIELDS
            ioc_type = 'Domain'
        # SHA-256, SHA-1 or MD5 identifying the file
        elif validation.Validation.validate_hash(ioc):
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            ioc_type = 'Hash'
        elif validation.Validation.validate_url(ioc):
            print(f'{ioc} recognized as URL')
            encoded_base64_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_base64_url}"
            ioc_type = 'URL'
        else:
            ioc_type = 'Not recognized'
            
        
        default_result = [ioc_type, ioc, 'Request failed. Please scan it manually']
        
        # Check if IoC format is recognized
        if not url:
            print(f'IOC {ioc} is not recognized')
            return [ioc_type,ioc, 'IOC is not recognized. Check IOC format']

        # Send a request
        response = requests.get(url, headers=headers)
        # Check if the request was successful
        if response.status_code != 200:
            # Submit to Virus Total if no data found
            if ioc_type == 'URL':
                # Send to Virus Total                   
                print(f'URL {ioc} has never been submitted to Virus Total. Sending {ioc} to Virus Total...')
                
                url = "https://www.virustotal.com/api/v3/urls"
                payload = { "url": ioc }
                headers = {
                    "accept": "application/json",
                    "x-apikey": self.vt_api_key,
                    "content-type": "application/x-www-form-urlencoded"
                }

                response = requests.post(url, data=payload, headers=headers)
                
                # Waiting for results
                print(f'Waiting for results {VirusTotal.URL_ANALIZE_TIME} seconds...')
                time.sleep(VirusTotal.URL_ANALIZE_TIME)
                
                # Get results
                headers = {"x-apikey": self.vt_api_key}
                url = f"https://www.virustotal.com/api/v3/urls/{encoded_base64_url}"
                encoded_base64_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                
                print(f'Requesting {ioc} scan results from Virus Total requesting URL encoded base64 {encoded_base64_url}...')
                # Send a request
                response = requests.get(url, headers=headers)

                # Check if the request was successful
                if response.status_code != 200:
                    # print(f"Request for {ioc} failed.\nError: {response.status_code} - {response.text}")
                    print(f"Request for URL {ioc} failed. Probably analize took more than estimated time, URL can have wrong format. Please, scan it manually")
                    
                    return default_result
            else:
                print(f"Request for {ioc} failed. Probably IOC has wrong format. Please, scan it manually")
                return default_result
                
        # Parse VT JSON
        response = json.loads(response.text)
            
        # Parsing Virus Total JSON    
        vt = {
            # 'tags':response['data']['attributes']['tags'],
            'harmless_score':response['data']['attributes']['last_analysis_stats']['harmless'],
            'malicious_score':response['data']['attributes']['last_analysis_stats']['malicious'],
            'suspicious_score':response['data']['attributes']['last_analysis_stats']['suspicious'],
            'undetected_score':response['data']['attributes']['last_analysis_stats']['undetected'],
        }    
            
        # Reputation check
        verdict = 'Clean'
        if int(vt['suspicious_score']) > 0:
            verdict = 'Suspicious'
        
        if int(vt['malicious_score']) > 0:
            verdict = 'Malicious'    

        # Return result based on type of IOC and report type
        if full_info:
            if ioc_type == 'Hash':
                return [ioc_type, ioc, verdict]
            if ioc_type == 'URL':
                domain = utils.Utils.get_domain_from_url(ioc)
                domain_scan = self.virus_total_info_check(domain)
                domain_scan_res = domain_scan[2]
                                
                return [ioc_type, ioc, f'Link:{verdict}; Domain:{domain_scan_res}', domain] + domain_scan[4:]
                # return [ioc_type, ioc, verdict, VirusTotal.get_domain_from_url(ioc)]
            try:
                whois = self.parse_main_whois_vt_info(response['data']['attributes']['whois'], whois_main_fields)
            except Exception as e:
                print(f'VirusTotal Whois info parse error. Error description: {e}')
                print(e)
                whois = {}
            if ioc_type == 'Domain':
                return [ioc_type,ioc, verdict, ioc] + list(vt.values()) + list(whois.values())
            if ioc_type == 'IP':
                return [ioc_type, ioc, verdict, whois_lookup_ipwhois.Whois.get_reverse_nslookup_info(ioc)] + list(vt.values()) + list(whois.values())   
        else:
            return [ioc_type, ioc, verdict]
        
        return default_result

   