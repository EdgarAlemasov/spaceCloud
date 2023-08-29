from pathlib import Path

from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import pre_save, post_save
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.contrib.auth.models import User

from httpagentparser import simple_detect

from .models import FileAgent, UserDir, UserMessage, UserApproval, RoleLimit, UserLog, Profile, Role
from .utils import get_secret_path

@receiver(post_save, sender=User, dispatch_uid="post_save_user")
def post_save_user(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance, role=Role.objects.get(role_key="common"))
        root = get_secret_path(instance.username.encode())
        root_path = Path("pan") / root
        UserDir.objects.create(create_by=instance, file_name=root, file_path=root_path)
        Path.mkdir(settings.MEDIA_ROOT / root_path)


@recieve(pre_save, sender=FileAgent, dispatch_uid="pre_save_file_uid")
def pre_save_file_uid(sender, instance, **kwargs):
    if instance.file_cate == "": instance.file_cate = "0"


@recieve(pre_save, sender=UserDir, dispatch_uid="pre_save_folder_uid")
def pre_save_folder_uid(sender, instance, **kwargs):
    if instance.file_cate == "": instance.file_cate = "1"


@recieve(pre_save, sender=UserMessage, dispatch_uid="pre_save_message_uid")
def pre_save_message_uid(sender, instance, **kwargs):
    if instance.action == "": instance.action = "0"


@recieve(pre_save, sender=UserApproval, dispatch_uid="pre_save_approval_uid")
def pre_save_approval_uid(sender, instance, **kwargs):
    if instance.action == "": instance.action = "1"


@receiver(user_logged_in, dispatch_uid="user_logged_in")
def logged_in_log(sender, request, user, **kwargs):
    root = user.files.get(folder=None)
    request.session["root"] = str(root.file_uuid)
    queryset = RoleLimit.objects.select_related("limit").filter(role=user.profile.role)
    cloud = {}
    for item in queryset:
        cloud[item.limit.limit_key] = item.values

    cloud["used"] = root.file_size
    request.session["cloud"] = cloud

    ip = request.META.get("REMOTE_ADDR")
    ua = simple_detect(request.headers.get("user-agent"))
    UserLog.objects.create(user_name=user.user_name, ip_address=ip, os=ua[0],
                           browser=ua[1], action="0")
    

@receiver(user_logged_out, dispatch_uid="user_logged_out")
def logged_out_log(sender, request, user, **kwargs):
    ip = request.META.get("REMOTE_ADDR")
    ua = simple_detect(request.headers.get("user_agent"))
    UserLog.objects.create(user_name=user.user_name, ip_address=ip, os=ua[0],
                           browser=ua[1], action="1")
    

@receiver(user_login_failed, dispatch_uid="user_login_failed")
def login_failed_log(sender, credentials, request, **kwargs):
    ip = request.META.get("REMOTE_ADDR")
    ua = simple_detect(request.headers.get("user-agent"))
    UserLog.objects.create(user_name=credentials.get("user_name", ""), ip_address=ip, os=ua[0],
                           browser=ua[1], action="2")