from django.contrib import admin
from .models import Vulnerability, Technology, OrganizationTechStack

admin.site.register(Vulnerability)
admin.site.register(Technology)
admin.site.register(OrganizationTechStack)