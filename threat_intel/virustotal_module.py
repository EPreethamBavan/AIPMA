"""
VirusTotal API Integration Module
Adapted for AIPMA Memory Analyzer
"""

import base64
import os

import requests

from . import configvars as cv
from .colors import mycolors, printr


class VirusTotalExtractor:
    urlfilevt3 = "https://www.virustotal.com/api/v3/files"
    urlurlvt3 = "https://www.virustotal.com/api/v3/urls"
    urlipvt3 = "https://www.virustotal.com/api/v3/ip_addresses"
    urldomainvt3 = "https://www.virustotal.com/api/v3/domains"

    def __init__(self, VTAPI):
        self.VTAPI = VTAPI

    def _make_request(self, url, method="GET", data=None, files=None):
        """Make HTTP request to VirusTotal API"""
        try:
            requestsession = requests.Session()
            requestsession.headers.update({"x-apikey": self.VTAPI})
            requestsession.headers.update({"content-type": "application/json"})

            if method == "GET":
                response = requestsession.get(url)
            elif method == "POST":
                if files:
                    requestsession.headers.pop("content-type", None)
                    response = requestsession.post(url, files=files)
                else:
                    response = requestsession.post(url, data=data)

            return response
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error connecting to VirusTotal: {e}{mycolors.reset}"
            )
            return None

    def vthashwork(self, myhash, showreport=1):
        """Query VirusTotal for hash information"""
        if len(myhash) not in [32, 40, 64]:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Invalid hash length. Must be MD5, SHA1, or SHA256.{mycolors.reset}"
            )
            return False

        url = f"{VirusTotalExtractor.urlfilevt3}/{myhash}"
        response = self._make_request(url)

        if not response or response.status_code == 404:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Hash not found in VirusTotal database.{mycolors.reset}"
            )
            return False

        try:
            vttext = response.json()
            attrs = vttext.get("data", {}).get("attributes", {})

            if showreport:
                self._display_file_report(attrs, myhash)
            else:
                return self._get_basic_detection(attrs)

            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error parsing VirusTotal response: {e}{mycolors.reset}"
            )
            return False

    def vtipwork(self, myip):
        """Query VirusTotal for IP information"""
        if not myip:
            return False

        url = f"{VirusTotalExtractor.urlipvt3}/{myip}"
        response = self._make_request(url)

        if not response or response.status_code == 404:
            print(
                f"{mycolors.foreground.error(cv.bkg)}IP not found in VirusTotal database.{mycolors.reset}"
            )
            return False

        try:
            vttext = response.json()
            attrs = vttext.get("data", {}).get("attributes", {})

            self._display_ip_report(attrs, myip)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error parsing VirusTotal response: {e}{mycolors.reset}"
            )
            return False

    def vtdomainwork(self, mydomain):
        """Query VirusTotal for domain information"""
        if not mydomain:
            return False

        url = f"{VirusTotalExtractor.urldomainvt3}/{mydomain}"
        response = self._make_request(url)

        if not response or response.status_code == 404:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Domain not found in VirusTotal database.{mycolors.reset}"
            )
            return False

        try:
            vttext = response.json()
            attrs = vttext.get("data", {}).get("attributes", {})

            self._display_domain_report(attrs, mydomain)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error parsing VirusTotal response: {e}{mycolors.reset}"
            )
            return False

    def vturlwork(self, myurl):
        """Query VirusTotal for URL information"""
        if not myurl:
            return False

        try:
            urlid = base64.urlsafe_b64encode(myurl.encode()).decode().strip("=")
            url = f"{VirusTotalExtractor.urlurlvt3}/{urlid}"
            response = self._make_request(url)

            if not response or response.status_code == 404:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}URL not found in VirusTotal database.{mycolors.reset}"
                )
                return False

            vttext = response.json()
            attrs = vttext.get("data", {}).get("attributes", {})

            self._display_url_report(attrs, myurl)
            return True
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error parsing VirusTotal response: {e}{mycolors.reset}"
            )
            return False

    def filechecking_v3(self, ffpname2, showreport=1, impexp=0, ovrly=0):
        """Check a file on VirusTotal"""
        if not ffpname2 or not os.path.isfile(ffpname2):
            print(
                f"{mycolors.foreground.error(cv.bkg)}File not found: {ffpname2}{mycolors.reset}"
            )
            return False

        try:
            # Calculate file hash
            import hashlib

            with open(ffpname2, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Query by hash first
            return self.vthashwork(file_hash, showreport)
        except Exception as e:
            print(
                f"{mycolors.foreground.error(cv.bkg)}Error processing file: {e}{mycolors.reset}"
            )
            return False

    def _display_file_report(self, attrs, file_hash):
        """Display file analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}VirusTotal File Report{mycolors.reset}"
        )
        printr()

        print(f"{mycolors.foreground.info(cv.bkg)}Hash: {mycolors.reset}{file_hash}")

        if "meaningful_name" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}File Name: {mycolors.reset}{attrs['meaningful_name']}"
            )

        if "size" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Size: {mycolors.reset}{attrs['size']} bytes"
            )

        if "type_description" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Type: {mycolors.reset}{attrs['type_description']}"
            )

        # Detection statistics
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            print(
                f"\n{mycolors.foreground.info(cv.bkg)}Detection Statistics:{mycolors.reset}"
            )
            print(f"  Malicious: {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
            print(f"  Undetected: {stats.get('undetected', 0)}")
            print(f"  Harmless: {stats.get('harmless', 0)}")

        # Top detections
        if "last_analysis_results" in attrs:
            self._display_av_detections(attrs["last_analysis_results"])

        printr()

    def _display_ip_report(self, attrs, ip):
        """Display IP analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}VirusTotal IP Report{mycolors.reset}"
        )
        printr()

        print(f"{mycolors.foreground.info(cv.bkg)}IP Address: {mycolors.reset}{ip}")

        if "country" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Country: {mycolors.reset}{attrs['country']}"
            )

        if "as_owner" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}AS Owner: {mycolors.reset}{attrs['as_owner']}"
            )

        if "asn" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}ASN: {mycolors.reset}{attrs['asn']}"
            )

        # Reputation
        if "reputation" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Reputation: {mycolors.reset}{attrs['reputation']}"
            )

        # Detection statistics
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            print(
                f"\n{mycolors.foreground.info(cv.bkg)}Detection Statistics:{mycolors.reset}"
            )
            print(f"  Malicious: {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
            print(f"  Undetected: {stats.get('undetected', 0)}")
            print(f"  Harmless: {stats.get('harmless', 0)}")

        # AV detections
        if "last_analysis_results" in attrs:
            self._display_av_detections(attrs["last_analysis_results"])

        printr()

    def _display_domain_report(self, attrs, domain):
        """Display domain analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}VirusTotal Domain Report{mycolors.reset}"
        )
        printr()

        print(f"{mycolors.foreground.info(cv.bkg)}Domain: {mycolors.reset}{domain}")

        if "categories" in attrs:
            cats = ", ".join(
                [f"{k}: {v}" for k, v in list(attrs["categories"].items())[:5]]
            )
            print(
                f"{mycolors.foreground.info(cv.bkg)}Categories: {mycolors.reset}{cats}"
            )

        if "reputation" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Reputation: {mycolors.reset}{attrs['reputation']}"
            )

        # Detection statistics
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            print(
                f"\n{mycolors.foreground.info(cv.bkg)}Detection Statistics:{mycolors.reset}"
            )
            print(f"  Malicious: {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
            print(f"  Undetected: {stats.get('undetected', 0)}")
            print(f"  Harmless: {stats.get('harmless', 0)}")

        # AV detections
        if "last_analysis_results" in attrs:
            self._display_av_detections(attrs["last_analysis_results"])

        printr()

    def _display_url_report(self, attrs, url):
        """Display URL analysis report"""
        printr()
        print(
            f"\n{mycolors.foreground.info(cv.bkg)}VirusTotal URL Report{mycolors.reset}"
        )
        printr()

        print(f"{mycolors.foreground.info(cv.bkg)}URL: {mycolors.reset}{url}")

        if "title" in attrs:
            print(
                f"{mycolors.foreground.info(cv.bkg)}Title: {mycolors.reset}{attrs['title']}"
            )

        # Detection statistics
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            print(
                f"\n{mycolors.foreground.info(cv.bkg)}Detection Statistics:{mycolors.reset}"
            )
            print(f"  Malicious: {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
            print(f"  Undetected: {stats.get('undetected', 0)}")
            print(f"  Harmless: {stats.get('harmless', 0)}")

        # AV detections
        if "last_analysis_results" in attrs:
            self._display_av_detections(attrs["last_analysis_results"])

        printr()

    def _display_av_detections(self, results):
        """Display AV detection results"""
        print(f"\n{mycolors.foreground.info(cv.bkg)}AV Detections:{mycolors.reset}")

        malicious_results = {
            k: v
            for k, v in results.items()
            if v.get("category") in ["malicious", "suspicious"]
        }

        if malicious_results:
            for av_name, result in list(malicious_results.items())[:10]:  # Show top 10
                category = result.get("category", "unknown")
                engine_name = result.get("engine_name", av_name)
                detection = result.get("result", "detected")

                color = (
                    mycolors.foreground.lightred
                    if cv.bkg == 1
                    else mycolors.foreground.red
                )
                if category == "suspicious":
                    color = mycolors.foreground.yellow

                print(f"  {color}{engine_name}: {detection}{mycolors.reset}")
        else:
            print(
                f"  {mycolors.foreground.green}No malicious detections{mycolors.reset}"
            )

    def _get_basic_detection(self, attrs):
        """Get basic detection statistics"""
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return f"{malicious}/{total}"
        return "N/A"
