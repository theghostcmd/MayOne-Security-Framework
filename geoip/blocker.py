import geoip2.database
import os
from config import GEOIP_DB_PATH, HIGH_RISK_COUNTRIES

class GeoIPBlocker:
    def __init__(self):
        self.reader = None
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self.reader = geoip2.database.Reader(GEOIP_DB_PATH)
                print("[GeoIP] Database loaded successfully.")
            except Exception as e:
                print(f"[GeoIP] Failed to load database: {e}")
        else:
            print(f"[GeoIP] Database not found at {GEOIP_DB_PATH}. GeoIP blocking disabled.")

    def get_country_code(self, ip):
        if not self.reader:
            return None
        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except:
            return None

    def is_high_risk(self, ip):
        if not self.reader:
            return False
        code = self.get_country_code(ip)
        return code in HIGH_RISK_COUNTRIES if code else False