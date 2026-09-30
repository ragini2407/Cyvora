import time
import requests

from datetime import datetime, timedelta

from django.utils import timezone
from django.core.management.base import BaseCommand

from accounts.models import Vulnerability


class Command(BaseCommand):
    help = "Fetch a controlled set of genuine CVEs from NVD API"

    def handle(self, *args, **options):

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # --------------------------------------------------
        # SETTINGS
        # --------------------------------------------------

        TARGET_TOTAL = 100

        # We scan NVD data and keep one genuine record only
        # when its severity is available.
        selected_cves = {}

        # Date range used for NVD collection
        start_date = datetime(2023, 1, 1)
        end_date = datetime(2025, 12, 31, 23, 59, 59)

        current_start = start_date

        self.stdout.write(
            self.style.SUCCESS(
                "\nStarting fresh NVD CVE collection..."
            )
        )

        # --------------------------------------------------
        # DATE CHUNKS
        # --------------------------------------------------

        while current_start <= end_date and len(selected_cves) < TARGET_TOTAL:

            current_end = min(
                current_start + timedelta(days=30),
                end_date
            )

            pub_start = current_start.strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )

            pub_end = current_end.strftime(
                "%Y-%m-%dT%H:%M:%S.999"
            )

            self.stdout.write(
                f"\nScanning NVD: {pub_start} -> {pub_end}"
            )

            start_index = 0

            # --------------------------------------------------
            # PAGINATION
            # --------------------------------------------------

            while len(selected_cves) < TARGET_TOTAL:

                params = {
                    "resultsPerPage": 100,
                    "startIndex": start_index,
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                }

                # --------------------------------------------------
                # REQUEST WITH RETRY
                # --------------------------------------------------

                max_retries = 5
                response = None

                for attempt in range(max_retries):

                    try:
                        response = requests.get(
                            url,
                            params=params,
                            timeout=60
                        )

                    except requests.exceptions.RequestException as e:

                        self.stderr.write(
                            self.style.ERROR(
                                f"Network error: {e}"
                            )
                        )

                        time.sleep(10)
                        continue

                    # SUCCESS
                    if response.status_code == 200:
                        break

                    # RATE LIMIT
                    if response.status_code == 429:

                        wait_time = 30 * (attempt + 1)

                        self.stdout.write(
                            self.style.WARNING(
                                f"NVD rate limit reached. "
                                f"Waiting {wait_time} seconds..."
                            )
                        )

                        time.sleep(wait_time)
                        continue

                    # OTHER ERROR
                    self.stderr.write(
                        self.style.ERROR(
                            f"NVD API error: {response.status_code}"
                        )
                    )

                    self.stderr.write(
                        f"Response: {response.text[:500]}"
                    )

                    return

                # --------------------------------------------------
                # REQUEST FAILED
                # --------------------------------------------------

                if response is None or response.status_code != 200:

                    self.stderr.write(
                        self.style.ERROR(
                            "NVD request failed after multiple retries."
                        )
                    )

                    return

                # --------------------------------------------------
                # JSON
                # --------------------------------------------------

                data = response.json()

                vulnerabilities = data.get(
                    "vulnerabilities",
                    []
                )

                total_results = data.get(
                    "totalResults",
                    0
                )

                # --------------------------------------------------
                # PROCESS CVEs
                # --------------------------------------------------

                for item in vulnerabilities:

                    if len(selected_cves) >= TARGET_TOTAL:
                        break

                    cve = item.get(
                        "cve",
                        {}
                    )

                    cve_id = cve.get("id")

                    if not cve_id:
                        continue

                    # --------------------------------------------------
                    # DESCRIPTION
                    # --------------------------------------------------

                    descriptions = cve.get(
                        "descriptions",
                        []
                    )

                    description = next(
                        (
                            d.get("value")
                            for d in descriptions
                            if d.get("lang") == "en"
                        ),
                        "No description available."
                    )

                    # --------------------------------------------------
                    # CVSS
                    # --------------------------------------------------

                    metrics = cve.get(
                        "metrics",
                        {}
                    )

                    cvss_score = None
                    severity = None

                    # CVSS 4.0
                    if "cvssMetricV40" in metrics:

                        cvss_data = metrics[
                            "cvssMetricV40"
                        ][0].get(
                            "cvssData",
                            {}
                        )

                        cvss_score = cvss_data.get(
                            "baseScore"
                        )

                        severity = cvss_data.get(
                            "baseSeverity"
                        )

                    # CVSS 3.1
                    elif "cvssMetricV31" in metrics:

                        cvss_data = metrics[
                            "cvssMetricV31"
                        ][0].get(
                            "cvssData",
                            {}
                        )

                        cvss_score = cvss_data.get(
                            "baseScore"
                        )

                        severity = cvss_data.get(
                            "baseSeverity"
                        )

                    # CVSS 3.0
                    elif "cvssMetricV30" in metrics:

                        cvss_data = metrics[
                            "cvssMetricV30"
                        ][0].get(
                            "cvssData",
                            {}
                        )

                        cvss_score = cvss_data.get(
                            "baseScore"
                        )

                        severity = cvss_data.get(
                            "baseSeverity"
                        )

                    # CVSS 2.0
                    elif "cvssMetricV2" in metrics:

                        cvss_data = metrics[
                            "cvssMetricV2"
                        ][0].get(
                            "cvssData",
                            {}
                        )

                        cvss_score = cvss_data.get(
                            "baseScore"
                        )

                        severity = metrics[
                            "cvssMetricV2"
                        ][0].get(
                            "baseSeverity"
                        )

                    # --------------------------------------------------
                    # ONLY KEEP RECORDS WITH REAL SEVERITY
                    # --------------------------------------------------

                    if not severity:
                        continue

                    severity = severity.upper()

                    if severity not in {
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "LOW"
                    }:
                        continue

                    # Avoid duplicate CVE IDs
                    if cve_id in selected_cves:
                        continue

                    # --------------------------------------------------
                    # PUBLISHED DATE
                    # --------------------------------------------------

                    published_str = cve.get(
                        "published"
                    )

                    published_date = None

                    if published_str:

                        try:

                            published_date = datetime.fromisoformat(
                                published_str.replace(
                                    "Z",
                                    "+00:00"
                                )
                            )

                            if timezone.is_naive(
                                published_date
                            ):

                                published_date = timezone.make_aware(
                                    published_date
                                )

                        except ValueError:

                            published_date = None

                    # --------------------------------------------------
                    # STORE TEMPORARILY
                    # --------------------------------------------------

                    selected_cves[cve_id] = {
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "published_date": published_date,
                    }

                # --------------------------------------------------
                # PAGINATION
                # --------------------------------------------------

                start_index += len(vulnerabilities)

                if (
                    not vulnerabilities
                    or start_index >= total_results
                ):
                    break

                time.sleep(2)

            # --------------------------------------------------
            # NEXT DATE CHUNK
            # --------------------------------------------------

            current_start = current_end + timedelta(
                seconds=1
            )

            time.sleep(3)

        # --------------------------------------------------
        # CHECK RESULT
        # --------------------------------------------------

        if len(selected_cves) < TARGET_TOTAL:

            self.stderr.write(
                self.style.ERROR(
                    f"\nOnly {len(selected_cves)} CVEs were collected."
                )
            )

            self.stderr.write(
                self.style.ERROR(
                    "Try running the command again."
                )
            )

            return

        # --------------------------------------------------
        # REMOVE OLD DATA
        # --------------------------------------------------

        old_count = Vulnerability.objects.count()

        Vulnerability.objects.all().delete()

        self.stdout.write(
            self.style.WARNING(
                f"\nRemoved {old_count} old vulnerability records."
            )
        )

        # --------------------------------------------------
        # SAVE FRESH 100 CVEs
        # --------------------------------------------------

        created = 0

        for cve_id, record in selected_cves.items():

            Vulnerability.objects.create(
                cve_id=cve_id,
                description=record["description"],
                cvss_score=record["cvss_score"],
                severity=record["severity"],
                published_date=record["published_date"],
            )

            created += 1

        # --------------------------------------------------
        # SHOW SEVERITY DISTRIBUTION
        # --------------------------------------------------

        severity_counts = {}

        for record in selected_cves.values():

            level = record["severity"]

            severity_counts[level] = (
                severity_counts.get(level, 0) + 1
            )

        self.stdout.write("\n--------------------------------")
        self.stdout.write(
            self.style.SUCCESS(
                "Fresh NVD dataset created successfully!"
            )
        )
        self.stdout.write("--------------------------------")

        self.stdout.write(
            f"Total CVEs: {created}"
        )

        self.stdout.write(
            f"CRITICAL: {severity_counts.get('CRITICAL', 0)}"
        )

        self.stdout.write(
            f"HIGH: {severity_counts.get('HIGH', 0)}"
        )

        self.stdout.write(
            f"MEDIUM: {severity_counts.get('MEDIUM', 0)}"
        )

        self.stdout.write(
            f"LOW: {severity_counts.get('LOW', 0)}"
        )

        self.stdout.write("--------------------------------")