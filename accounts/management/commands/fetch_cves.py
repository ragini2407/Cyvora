import time
import requests

from datetime import datetime, timedelta

from django.utils import timezone
from django.core.management.base import BaseCommand

from accounts.models import Vulnerability


class Command(BaseCommand):

    help = "Fetch CVEs from NVD API and store them in the database"

    def handle(self, *args, **options):

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # --------------------------------------------------
        # DATE RANGE
        # --------------------------------------------------

        start_date = datetime(2023, 1, 1)
        end_date = datetime(2025, 12, 31, 23, 59, 59)

        current_start = start_date

        total_created = 0
        total_updated = 0

        self.stdout.write(
            self.style.SUCCESS(
                "Starting NVD CVE data fetch..."
            )
        )

        # --------------------------------------------------
        # DATE CHUNKS
        # --------------------------------------------------

        while current_start <= end_date:

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
                f"\nFetching: {pub_start} -> {pub_end}"
            )

            start_index = 0

            # --------------------------------------------------
            # PAGINATION
            # --------------------------------------------------

            while True:

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
                                f"NVD rate limit reached (429). "
                                f"Waiting {wait_time} seconds..."
                            )
                        )

                        time.sleep(wait_time)
                        continue

                    # OTHER ERROR
                    self.stderr.write(
                        self.style.ERROR(
                            f"NVD API error: "
                            f"{response.status_code}"
                        )
                    )

                    self.stderr.write(
                        f"NVD message: "
                        f"{response.headers.get('message', 'No message')}"
                    )

                    self.stderr.write(
                        f"Response: "
                        f"{response.text[:500]}"
                    )

                    return

                # --------------------------------------------------
                # IF STILL NOT SUCCESSFUL
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

                            # Make sure datetime is timezone-aware
                            if timezone.is_naive(
                                published_date
                            ):

                                published_date = timezone.make_aware(
                                    published_date
                                )

                        except ValueError:

                            published_date = None

                    # --------------------------------------------------
                    # SAVE / UPDATE
                    # --------------------------------------------------

                    obj, created = (
                        Vulnerability.objects.update_or_create(
                            cve_id=cve_id,
                            defaults={
                                "description": description,
                                "cvss_score": cvss_score,
                                "severity": severity,
                                "published_date": published_date,
                            }
                        )
                    )

                    if created:

                        total_created += 1

                    else:

                        total_updated += 1

                # --------------------------------------------------
                # PAGINATION
                # --------------------------------------------------

                start_index += len(vulnerabilities)

                if (
                    not vulnerabilities
                    or start_index >= total_results
                ):
                    break

                # Small pause between pages
                time.sleep(6)

            # --------------------------------------------------
            # NEXT DATE CHUNK
            # --------------------------------------------------

            current_start = current_end + timedelta(
                seconds=1
            )

            # Important: pause between date chunks
            time.sleep(10)

        # --------------------------------------------------
        # FINAL RESULT
        # --------------------------------------------------

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone! "
                f"{total_created} new CVEs added, "
                f"{total_updated} CVEs updated."
            )
        )