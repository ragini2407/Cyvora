from django.core.management.base import BaseCommand
from accounts.models import Technology

TECH_LIST = [
    "Apache", "Nginx", "PostgreSQL", "MySQL", "Django",
    "Windows Server", "Linux (Ubuntu)", "React", "Node.js",
    "PHP", "WordPress", "Docker", "Kubernetes", "AWS", "Azure",
]

class Command(BaseCommand):
    help = "Seed initial technology list"

    def handle(self, *args, **options):
        created_count = 0
        for tech in TECH_LIST:
            obj, created = Technology.objects.get_or_create(name=tech)
            if created:
                created_count += 1
        self.stdout.write(self.style.SUCCESS(f"{created_count} technologies added."))