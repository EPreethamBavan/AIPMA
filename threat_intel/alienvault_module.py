"""
AlienVault OTX API Integration Module
Adapted for AIPMA Memory Analyzer
"""

import textwrap

import requests

from . import configvars as cv
from .colors import mycolors, printr


class AlienVaultExtractor:
    urlalien = "http://otx.alienvault.com/api/v1"

    def __init__(self, ALIENAPI):
        self.ALIENAPI = ALIENAPI

    def _make_request(self, endpoint, params=None):
        """Make HTTP request to AlienVault OTX API"""
        try:
            headers = {"X-OTX-API-KEY": self.ALIENAPI}
            url = f"{AlienVaultExtractor.urlalien}/{endpoint}"

            requestsession = requests.Session()
            requestsession.headers.update({"Content-Type": "application/json"})
            response = requestsession.post(url=url, headers=headers, params=params)

            return response.json()
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error connecting to AlienVault: {e}{mycolors.reset}"
            )
            return None

    def alien_ipv4(self, ip):
        """Query AlienVault OTX for IP information"""
        if not ip:
            return False

        try:
            hatext = self._make_request(f"indicators/IPv4/{ip}", {"limit": "10"})

            if not hatext or "sections" not in hatext:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}IP not found in AlienVault OTX.{mycolors.reset}"
                )
                return False

            self._display_ip_report(hatext)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying AlienVault: {e}{mycolors.reset}"
            )
            return False

    def alien_domain(self, domain):
        """Query AlienVault OTX for domain information"""
        if not domain:
            return False

        try:
            hatext = self._make_request(f"indicators/domain/{domain}", {"limit": "10"})

            if not hatext or "indicator" not in hatext:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}Domain not found in AlienVault OTX.{mycolors.reset}"
                )
                return False

            self._display_domain_report(hatext)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying AlienVault: {e}{mycolors.reset}"
            )
            return False

    def alien_hash(self, file_hash):
        """Query AlienVault OTX for hash information"""
        if not file_hash:
            return False

        try:
            hatext = self._make_request(f"indicators/file/{file_hash}", {"limit": "10"})

            if not hatext or "indicator" not in hatext:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}Hash not found in AlienVault OTX.{mycolors.reset}"
                )
                return False

            self._display_hash_report(hatext)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying AlienVault: {e}{mycolors.reset}"
            )
            return False

    def alien_url(self, url):
        """Query AlienVault OTX for URL information"""
        if not url:
            return False

        try:
            hatext = self._make_request(
                f"indicators/url/{url}/general", {"limit": "10"}
            )

            if not hatext or "indicator" not in hatext:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}URL not found in AlienVault OTX.{mycolors.reset}"
                )
                return False

            self._display_url_report(hatext)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying AlienVault: {e}{mycolors.reset}"
            )
            return False

    def alien_subscribed(self, limit):
        """Get subscribed pulses from AlienVault OTX"""
        try:
            limit_value = int(limit)
        except:
            limit_value = 10

        try:
            hatext = self._make_request(
                "pulses/subscribed", {"limit": str(limit_value)}
            )

            if not hatext or "results" not in hatext:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}No subscribed pulses found.{mycolors.reset}"
                )
                return False

            self._display_pulses(hatext)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error querying AlienVault: {e}{mycolors.reset}"
            )
            return False

    def _display_ip_report(self, data):
        """Display IP analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}AlienVault OTX IP Report{mycolors.reset}"
        )
        printr()

        if "asn" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}ASN: {mycolors.reset}{data['asn']}"
            )

        if "city" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}City: {mycolors.reset}{data['city']}"
            )

        if "country_name" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Country: {mycolors.reset}{data['country_name']}"
            )

        if "pulse_info" in data:
            pulse_info = data["pulse_info"]
            if "count" in pulse_info:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Pulse Count: {mycolors.reset}{pulse_info['count']}"
                )

            if "pulses" in pulse_info and pulse_info["pulses"]:
                print(
                    f"\n{mycolors.foreground.info(cv.bkg)}Related Pulses:{mycolors.reset}"
                )
                for pulse in pulse_info["pulses"][:5]:  # Show top 5
                    if "name" in pulse:
                        print(f"  • {pulse['name']}")

        printr()

    def _display_domain_report(self, data):
        """Display domain analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}AlienVault OTX Domain Report{mycolors.reset}"
        )
        printr()

        if "indicator" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Domain: {mycolors.reset}{data['indicator']}"
            )

        if "alexa" in data and data["alexa"]:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Alexa Rank: {mycolors.reset}{data['alexa']}"
            )

        if "pulse_info" in data:
            pulse_info = data["pulse_info"]
            if "count" in pulse_info:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Pulse Count: {mycolors.reset}{pulse_info['count']}"
                )

            if "pulses" in pulse_info and pulse_info["pulses"]:
                print(
                    f"\n{mycolors.foreground.info(cv.bkg)}Related Pulses:{mycolors.reset}"
                )
                for pulse in pulse_info["pulses"][:5]:
                    if "name" in pulse:
                        print(f"  • {pulse['name']}")
                    if "description" in pulse and pulse["description"]:
                        desc = (
                            pulse["description"][:100] + "..."
                            if len(pulse["description"]) > 100
                            else pulse["description"]
                        )
                        print(f"    {desc}")

        printr()

    def _display_hash_report(self, data):
        """Display hash analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}AlienVault OTX Hash Report{mycolors.reset}"
        )
        printr()

        if "indicator" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Hash: {mycolors.reset}{data['indicator']}"
            )

        if "pulse_info" in data:
            pulse_info = data["pulse_info"]
            if "count" in pulse_info:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Pulse Count: {mycolors.reset}{pulse_info['count']}"
                )

            if "pulses" in pulse_info and pulse_info["pulses"]:
                print(
                    f"\n{mycolors.foreground.info(cv.bkg)}Related Pulses:{mycolors.reset}"
                )
                for pulse in pulse_info["pulses"][:5]:
                    if "name" in pulse:
                        print(f"  • {pulse['name']}")
                    if "description" in pulse and pulse["description"]:
                        desc = (
                            pulse["description"][:100] + "..."
                            if len(pulse["description"]) > 100
                            else pulse["description"]
                        )
                        print(f"    {desc}")
                    if "malware_families" in pulse and pulse["malware_families"]:
                        families = ", ".join(pulse["malware_families"][:3])
                        print(f"    Malware Families: {families}")

        printr()

    def _display_url_report(self, data):
        """Display URL analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}AlienVault OTX URL Report{mycolors.reset}"
        )
        printr()

        if "indicator" in data:
            print(
                f"{mycolors.foreground.info(cv.bkg)}URL: {mycolors.reset}{data['indicator']}"
            )

        if "alexa" in data and data["alexa"]:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Alexa Rank: {mycolors.reset}{data['alexa']}"
            )

        if "pulse_info" in data:
            pulse_info = data["pulse_info"]
            if "count" in pulse_info:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Pulse Count: {mycolors.reset}{pulse_info['count']}"
                )

            if "pulses" in pulse_info and pulse_info["pulses"]:
                print(
                    f"\n{mycolors.foreground.info(cv.bkg)}Related Pulses:{mycolors.reset}"
                )
                for pulse in pulse_info["pulses"][:5]:
                    if "name" in pulse:
                        print(f"  • {pulse['name']}")

        printr()

    def _display_pulses(self, data):
        """Display subscribed pulses"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}AlienVault OTX Subscribed Pulses{mycolors.reset}"
        )
        printr()

        if "results" not in data:
            return

        for i, pulse in enumerate(data["results"], 1):
            print(f"\n{mycolors.foreground.info(cv.bkg)}Pulse #{i}{mycolors.reset}")
            print("-" * 50)

            if "name" in pulse:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Name: {mycolors.reset}{pulse['name']}"
                )

            if "description" in pulse and pulse["description"]:
                desc_lines = textwrap.wrap(pulse["description"], width=80)
                print(f"{mycolors.foreground.info(cv.bkg)}Description:{mycolors.reset}")
                for line in desc_lines[:3]:  # Show first 3 lines
                    print(f"  {line}")

            if "tags" in pulse and pulse["tags"]:
                tags = ", ".join(pulse["tags"][:5])
                print(f"{mycolors.foreground.info(cv.bkg)}Tags: {mycolors.reset}{tags}")

            if "created" in pulse:
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Created: {mycolors.reset}{pulse['created']}"
                )

            if "malware_families" in pulse and pulse["malware_families"]:
                families = ", ".join(pulse["malware_families"])
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Malware Families: {mycolors.reset}{families}"
                )

            if "industries" in pulse and pulse["industries"]:
                industries = ", ".join(pulse["industries"])
                print(
                    f"{mycolors.foreground.info(cv.bkg)}Industries: {mycolors.reset}{industries}"
                )

        printr()
