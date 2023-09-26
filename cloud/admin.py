from typing import Any, Dict, Tuple
from django.contrib import admin, messages
from django.contrib.admin.models import LogEntry
from django.db.models.query import QuerySet
from django.http.request import HttpRequest
from django.utils.translation import ngettext
from .models import (Profile, Role, NameLimit, RoleLimit, FileType,
                     UserFile, FileAgent, UserDir, FileShare,
                     ShareRecord, Notice, Message, UserMessage, UserApproval, UserLog)

@admin.action(description="Restore selected file")
def make_recycle(model_admin, request, queryset):
    rows = queryset.update(delete_flag="0", update_by=request.user)
    model_admin.message_user(request, ngettext(
        f"{rows} file restored",
        f"{rows} file resotred",
        rows
    ), messages.SUCCESS)

@admin.action(description="Restore selected file")
def make_removed(model_admin, request, queryset):
    rows = queryset.update(delete_flag="1", update_by=request.user)
    model_admin.message_user(request, ngettext(
        f"{rows} file restored",
        f"{rows} file restored",
        rows
    ), messages.SUCCESS)

@admin.action(description="Submit app")
def make_pass(model_admin, request, queryset):
    role = Role.objects.get(role_key="member")
    profiles = list(map(lambda item: item.create_by.profile, queryset))
    rows = queryset.update(state="1", update_by=request.user)
    for page in profiles:
        page.role = role

    Profile.objects.bulk_update(profiles, ("role",))
    model_admin.message_user(request, ngettext(
        f"Done {rows} app",
        f"Done {rows} app",
        rows
    ), messages.SUCCESS)

@admin.action(description="Reject app")
def make_notpass(model_admin, request, queryset):
    rows = queryset.update(state="2", update_by=request.user)
    model_admin.message_user(request, ngettext(
        f"Rejected {rows} app",
        f"Rejected {rows} app",
        rows
    ), messages.SUCCESS)

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = [
        "object_repr",
        "object_id",
        "action_flag",
        "user",
        "change_message"
    ]
    list_per_page = 12

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main ingormation", {
            "fields": ("user", "avatar", "gender", "role")
        }),
        ("Other information", {
            "fields": ("create_time", "update_by", "update_time", "remark")
        })
    )
    autocomplete_fields = ("user",)
    search_fields = ("user__username", )
    readonly_fields = ("create_time", "update_by", "update_time")
    list_select_related = ("user",)
    list_display = ("user", "role", "gender")
    list_filter = ("gender", "role")
    list_per_page = 10


    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        obj.update_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Role)
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

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)

@admin.register(NameLimit)
class LimitAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("name_limit", "name_key")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_display = ("name_limit", "name_key")
    list_per_page = 10


    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)

@admin.register(RoleLimit)
class RoleLimitAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("role", "limit", "value")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_select_related = ("role", "limit")
    list_display = ("role", "limit", "value")
    list_filter = ("role", "limit")
    list_per_page = 10

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)

@admin.register(FileType)
class FileTypeAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("type_name", "suffix")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_display = ("type_name", "suffix")
    list_per_page = 10

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)

@admin.register(UserFile)
class UserFile(admin.ModelAdmin):
    search_fields = ("file_name", "file_path")

    def get_model_perms(self, request: HttpRequest) -> Dict[str, bool]:
        return {}
    
    def get_search_results(self, request: HttpRequest, queryset: QuerySet[Any], search_term: str) -> Tuple[QuerySet[Any], bool]:
        if request.GET.get("model_name") == "fileshare":
            return super().get_search_results(request, queryset, search_term)
        queryset =queryset.filter(file_cate=1)
        return super().get_search_results(request, queryset, search_term)
    

@admin.register(FileAgent)
class FileAgentAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("file_uuid", "file_name", "file_type", "file_size", "file_path", "folder", "delete_flag")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    autocomplete_fields = ("folder",)
    search_fields = ("file_name", "create_by__username")
    readonly_fields = ("file_uuid", "create_by", "create_time", "update_by", "update_time")
    actions = [make_removed, make_recycle]
    list_select_related = ("create_by",)
    list_display = ("file_name", "file_type", "file_size", "delete_flag", "create_by")
    list_filter = ("file_type", "delete_flag")
    list_per_page = 10


    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)


@admin.register(UserDir)
class UserDirAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("file_uuid", "file_name", "file_size", "file_path", "folder", "delete_flag")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    autocomplete_fields = ("folder",)
    search_fields = ("file_name", "create_by__username")
    readonly_fields = ("file_uuid", "create_by", "create_time", "update_by", "update_time")
    actions = [make_removed, make_recycle]
    list_select_related = ("create_by",)
    list_display = ("file_name", "file_size", "delete_flag", "create_by")
    list_filter = ("delete_flag",)
    list_per_page = 10

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)


@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("secret_key", "signature", "expire_time", "user_file", "summary")
        }),
        ("Other information", {
            "fields": ("create_time", "update_by", "update_time", "remark")
        })
    )
    autocomplete_fields = ("user_file",)
    search_fields = ("user_file__create_by__username", "user_file__file_name")
    readonly_fields = ("secret_key", "signature", "create_time", "update_by", "update_time")
    list_select_related = ("user_file",)
    list_display = ("user_file", "create_time", "expire_time")
    list_filter = ("user_file__file_type", "user_file__file_cate")
    list_per_page = 10

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        obj.update_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ShareRecord)
class ShareRecordAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("file_share", "recipient", "anonymous")
        }),
        ("Other information", {
            "fields": ("create_time", "update_by", "update_time", "remark")
        })
    )
    search_fields = ("recipient__username", "file_share__user_file_name")
    readonly_fields = ("create_time", "update_by", "update_time")
    list_select_related = ("file_share", "recipient")
    list_display = ("file_share", "recipient", "anonymous")
    list_filter = ("file_share__user_file__file_type", "file_share__user_file__file_cate")
    list_per_page = 10

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        obj.update_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Notice)
class NoticeAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("title", "content")
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    search_fields = ("create_by__username", "notice_title")
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_select_related = ("create_by",)
    list_display = ("title", "create_by")
    list_per_page = 10

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not obj.create_by:
            obj.create_by = request.user
        obj.update_by = request.user

        super().save_model(request, obj, form, change)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    def get_model_perms(self, request: HttpRequest) -> Dict[str, bool]:
        return {}
    

@admin.register(UserMessage)
class UserMessageAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("content",)
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    search_fields = ("create_by__username",)
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    list_select_related = ("create_by",)
    list_display = ("create_by", "create_time")
    list_per_page = 10

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        obj.update_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(UserApproval)
class UserApprovalAdmin(admin.ModelAdmin):
    fieldsets = (
        ("Main information", {
            "fields": ("state", "content",)
        }),
        ("Other information", {
            "fields": ("create_by", "create_time", "update_by", "update_time", "remark")
        })
    )
    search_fields = ("create_by__username",)
    readonly_fields = ("create_by", "create_time", "update_by", "update_time")
    actions = (make_pass, make_notpass)
    list_select_related = ("create_by",)
    list_display = ("create_by", "state", "create_time")
    list_per_page = 10

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
    
    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        obj.update_by = request.user
        super().save_model(request, obj, form, change)

        profile = obj.create_by.profile
        if obj.state == "1": profile.role = Role.objects.get(role_key="member")
        else: profile.role = Role.objects.get(role_key="common")
        profile.save()

@admin.register(UserLog)
class UserLogAdmin(admin.ModelAdmin):
    search_fields = ("username",)
    list_display = ("username", "ip_address", "browser", "os", "action", "action_time")
    list_filter = ("action",)
    list_per_page = 15

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False