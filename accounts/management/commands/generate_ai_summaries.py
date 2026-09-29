from django.core.management.base import BaseCommand
from accounts.models import Vulnerability
from accounts.ai_utils import generate_ai_summary_and_recommendation
import time


class Command(BaseCommand):
    help = "Generate AI summaries and recommendations for vulnerabilities"

    def handle(self, *args, **options):

        vulnerabilities = Vulnerability.objects.all()
        total = vulnerabilities.count()

        self.stdout.write(
            self.style.SUCCESS(
                f"Generating AI summaries for {total} vulnerabilities..."
            )
        )

        success = 0
        failed = 0

        for i, vuln in enumerate(vulnerabilities, start=1):

            # Already valid AI summary hai to skip
            if (
                vuln.ai_summary
                and not vuln.ai_summary.startswith("Error generating summary:")
            ):
                self.stdout.write(
                    f"[{i}/{total}] {vuln.cve_id} - already done, skipped."
                )
                success += 1
                continue

            summary, recommendation = generate_ai_summary_and_recommendation(
                vuln.cve_id,
                vuln.description,
                vuln.severity,
                vuln.cvss_score
            )

            # Error ko database mein save MAT karo
            if summary.startswith("Error generating summary:"):
                self.stdout.write(
                    self.style.ERROR(
                        f"[{i}/{total}] {vuln.cve_id} - AI FAILED"
                    )
                )
                failed += 1
                continue

            vuln.ai_summary = summary
            vuln.ai_recommendation = recommendation
            vuln.save()

            success += 1

            self.stdout.write(
                self.style.SUCCESS(
                    f"[{i}/{total}] {vuln.cve_id} - AI done."
                )
            )

            time.sleep(1)

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Completed! Success: {success} | Failed: {failed}"
            )
        )