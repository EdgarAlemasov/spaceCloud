from django.contrib import admin
from .models import Role

# Register your models here.
class RoleAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("role_name", "role_key")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_time", "update_by", "comments")
        })
    )
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_display = ("role_name", "role_key")
    list_per_page = 15

    def save_model(self, request, object, form, change):
        if not object.create_by:
            object.create_by = request.user
        object.update_by = request.user

        super().save_model(request, object, form, change)
