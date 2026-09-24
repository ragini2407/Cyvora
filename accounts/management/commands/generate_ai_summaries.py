from django.core.management.base import BaseCommand
from accounts.models import Vulnerability
from accounts.ai_utils import generate_ai_summary_and_recommendation
import time


class Command(BaseCommand):
    help = "Generate AI summaries and recommendations for vulnerabilities missing them"

    def handle(self, *args, **options):
        vulnerabilities = Vulnerability.objects.filter(ai_summary__isnull=True) | Vulnerability.objects.filter(ai_summary="")

        total = vulnerabilities.count()
        self.stdout.write(f"Generating AI summaries for {total} vulnerabilities...")

        for i, vuln in enumerate(vulnerabilities, start=1):
            summary, recommendation = generate_ai_summary_and_recommendation(
                vuln.cve_id, vuln.description, vuln.severity, vuln.cvss_score
            )
            vuln.ai_summary = summary
            vuln.ai_recommendation = recommendation
            vuln.save()

            self.stdout.write(f"[{i}/{total}] {vuln.cve_id} done.")
            time.sleep(1)

        self.stdout.write(self.style.SUCCESS("All AI summaries generated."))