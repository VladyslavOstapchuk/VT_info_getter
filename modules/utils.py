from modules import validation
from urllib.parse import urlparse

class Utils:
    @staticmethod
    def time_formatter(seconds: float) -> str:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
    
    @staticmethod
    def get_domain_from_url(url: str):
        if not validation.Validation.validate_url(url):
            return None
        
        return urlparse(url).netloc