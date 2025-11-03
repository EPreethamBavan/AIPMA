"""
IPInfo.io API Integration Module
Adapted for AIPMA Memory Analyzer
"""

import requests

from . import configvars as cv
from .colors import mycolors


class IPInfoExtractor:
    def __init__(self, IPINFOAPI):
        self.IPINFOAPI = IPINFOAPI if IPINFOAPI else ""

    def get_ip_details(self, ip_address):
        """Get IP address details from IPInfo.io"""
        try:
            # IPInfo.io allows 1000 requests per day without API key
            if self.IPINFOAPI:
                url = f"https://ipinfo.io/{ip_address}?token={self.IPINFOAPI}"
            else:
                url = f"https://ipinfo.io/{ip_address}"

            response = requests.get(url)

            if response.status_code != 200:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}Error: Unable to retrieve IP information (Status: {response.status_code}){mycolors.reset}"
                )
                return False

            data = response.json()

            if "error" in data:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}Error: {data['error'].get('message', 'Unknown error')}{mycolors.reset}"
                )
                return False

            self._display_ip_report(data)
            return True

        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying IPInfo: {str(e)}{mycolors.reset}"
            )
            return False

    def _display_ip_report(self, data):
        """Display IP information report"""
        print()
        print(f"{mycolors.foreground.info(cv.bkg)}{'='*50}{mycolors.reset}")
        print(
            f"{mycolors.foreground.info(cv.bkg)}IPInfo.io Report{mycolors.reset}".center(
                50
            )
        )
        print(f"{mycolors.foreground.info(cv.bkg)}{'='*50}{mycolors.reset}")
        print()

        fields = [
            ("ip", "IP Address"),
            ("hostname", "Hostname"),
            ("city", "City"),
            ("region", "Region"),
            ("country", "Country"),
            ("loc", "Location"),
            ("org", "Organization"),
            ("postal", "Postal Code"),
            ("timezone", "Timezone"),
        ]

        for field_key, field_label in fields:
            if field_key in data and data[field_key]:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}{field_label}: {mycolors.reset}{data[field_key]}"
                )

        print()
        print(f"{mycolors.foreground.info(cv.bkg)}{'='*50}{mycolors.reset}")
        print()
