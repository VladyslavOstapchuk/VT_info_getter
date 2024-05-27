from ipwhois import IPWhois
import whois
from nslookup import Nslookup
import dns.resolver, dns.reversename
from modules import validation
from iplookup import iplookup

class Whois:
    @staticmethod
    def get_nslookup_info(domain: str):
        result = None
        
        if not validation.Validation.validate_domain(domain):
            return None

        try:
            ip = iplookup.iplookup
            result = ip(domain)[0]
        except:
            print(f'{domain} nslookup request failed')
            
        return result

    @staticmethod
    def get_reverse_nslookup_info(ip: str):
        result = None
        
        if not validation.Validation.validate_ip(ip):
            return None
        
        try:
            result = str(dns.resolver.resolve(dns.reversename.from_address(ip),"PTR")[0])
        except:
            print(f'{ip} reverse nslookup request failed')
        
        if result:
            result = result[:-1]
        
        return result

    @staticmethod
    def ns_lookup(ip_domain: str):
        if validation.Validation.validate_domain(ip_domain):
            return Whois.get_nslookup_info(ip_domain)
        elif validation.Validation.validate_ip():
            return Whois.get_reverse_nslookup_info(ip_domain)
        
        return None

    @staticmethod
    def get_whois_main_ip_info(ip: str):
        try:
            full_info = IPWhois(ip).lookup_rdap()
            
            country = full_info['asn_country_code']
            asn_description = full_info['asn_description']
            asn_cidr = full_info['asn_cidr']
            created = full_info['network']['events'][0]['timestamp']
            last_changed = full_info['network']['events'][0]['timestamp']
            
            result = [ip, Whois.get_reverse_nslookup_info(ip) ,country, asn_description, asn_cidr, created, last_changed]
        
        # In case if request with IPWhois fails try whois
        except Exception as e:
            print(f'Error occured during request to whois for {ip}. Error description: {e}')
            print(f'Retry to get information from whois for {ip}...')
            try:
                full_info = whois.whois(ip)
                result = [ip, full_info.country, full_info.registrar, None, full_info.creation_date, full_info.updated_date]
                
                # Check if result contains any data from whois
                whois_hidden = True
                for value in result:
                    if value != None:
                        whois_hidden = False
                        break
                
                if whois_hidden:   
                    print(f'Retry was successfull. Information about {ip} was obtained')
                else:
                    print(f'Retry to obtain information about {ip} failed. It looks like whois information for {ip} is hidden')
            except:
                print(f'Retry failed. {ip} is not known. Try out to find information manually')
                result = [ip, None, None, None, None, None]

        return result

    @staticmethod
    def get_whois_main_domain_info(domain:str):
        try:
            ip = Whois.get_nslookup_info(domain)
            
            if ip != None and validation.Validation.validate_ip(ip):
                result = Whois.get_whois_main_ip_info(ip)
                result[1] = domain
            else:
                full_info = whois.whois(domain)
                result = [domain, full_info.country, full_info.registrar, None, full_info.creation_date, full_info.updated_date]
        except Exception as e:
            print(f'Error occured during request to whois for {domain}. Error description: {e}')
            result = [domain,None,None,None,None,None,None]
    
        return result

    @staticmethod
    def get_whois_main_info(ip_or_domain: str):
        if validation.Validation.validate_ip(ip_or_domain):
            return Whois.get_whois_main_ip_info(ip_or_domain)
        else:
            return Whois.get_whois_main_domain_info(ip_or_domain)
    
    @staticmethod
    def bulk_get_whois_main_info(ip_or_domain_list: list):
        result = []
        counter = len(ip_or_domain_list)
        
        for row in ip_or_domain_list:
            counter = counter - 1
            result.append(Whois.get_whois_main_info(row))
            if counter != 0:
                    print(f'{counter} IP/Domains to check remaining.')

        return result
