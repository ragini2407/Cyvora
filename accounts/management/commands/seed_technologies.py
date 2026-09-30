from django.core.management.base import BaseCommand
from accounts.models import Technology


TECH_LIST = {
    "os": [
        "Windows Server",
        "Linux (Ubuntu)",
    ],

    "web": [
        "Apache",
        "Nginx",
        "Django",
        "React",
        "Node.js",
        "PHP",
        "WordPress",
    ],

    "database": [
        "PostgreSQL",
        "MySQL",
    ],

    "language": [
        "Python",
    ],

    "cloud": [
        "AWS",
        "Azure",
        "Docker",
        "Kubernetes",
    ],

    "security": [],
}


class Command(BaseCommand):
    help = "Seed and categorize initial technology list"

    def handle(self, *args, **options):
        created_count = 0
        updated_count = 0

        for category, technologies in TECH_LIST.items():

            for tech_name in technologies:

                # Find all records with this technology name
                objects = Technology.objects.filter(name=tech_name)

                if objects.exists():

                    # Update all existing duplicates safely
                    for obj in objects:
                        if obj.category != category:
                            obj.category = category
                            obj.save(update_fields=["category"])
                            updated_count += 1

                else:
                    # Create if technology does not exist
                    Technology.objects.create(
                        name=tech_name,
                        category=category
                    )
                    created_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Technology setup completed. "
                f"Created: {created_count}, Updated: {updated_count}"
            )
        )