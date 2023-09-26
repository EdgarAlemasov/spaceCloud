from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.contrib.auth.models import User

from .utils import get_uuid, get_unique_filename


def get_delete_user():
    return User.objects.get_or_create(username="anonymous", defaults={
        "password": "anonymous"
    })[0]

def get_delete_role():
    return Role.objects.get_or_create(role_key="anonymous", defaults={
        "role_name": "anonymous"
    })[0]

def get_delete_user_file():
    return UserFile.objects.get_or_create(file_name="anonymous", created_by=None, defaults={
        "file_uuid": get_uuid(),
        "file_cate": "0",
        "file_size": 0,
        "file_path": "anonymous"
    })[0]

def get_delete_file_type():
    return FileType.objects.get_or_create(suffix="", defaults={
        "type_name": "unknown"
    })[0]

def get_delete_file_share():
    return FileShare.objects.get_or_create(secret_key="anonymous", defaults={
        "signature": "anonymous",
        "user_file": get_delete_user_file(),
        "expire_time": timezone.now()
    })[0]


class BaseModel(models.Model):
    create_time = models.DateTimeField(auto_now_add=True, verbose_name="Time creating")
    update_time = models.DateTimeField(auto_now=True, verbose_name="Updating time")
    create_by = models.ForeignKey(User, on_delete=models.SET(get_delete_user), blank=True,
                                  null=True, related_name="+", verbose_name="Creator")
    update_by = models.ForeignKey(User, on_delete=models.SET(get_delete_user), blank=True,
                                  null=True, related_name="+", verbose_name="Changed")
    comments = models.TextField(blank=True, verbose_name="Comments")

    class Meta:
        abstract = True

class Role(BaseModel):
    role_name = models.CharField(max_length=50, verbose_name="Role_name")
    role_key = models.CharField(unique=True, max_length=50, verbose_name="Role_key")

    class Meta:
        verbose_name = "Role"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.role_name


class NameLimit(BaseModel):
    name_limit = models.CharField(max_length=50, verbose_name="name restriction")
    name_key = models.CharField(unique=True, max_length=50, verbose_name="symbols restriction")


    class Meta:
        verbose_name = "Conditions"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.name_limit
    

class RoleLimit(BaseModel):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name="role")
    limit = models.ForeignKey(NameLimit, on_delete=models.CASCADE, verbose_name="restriction")
    value = models.BigIntegerField(verbose_name="value")


    class Meta:
        verbose_name = "role restrictions"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return f"role: {self.role.role_key}, limit: {self.limit.name_key}"
    

class Profile(BaseModel):
    create_by = None 
    GENDER = [
        ("0", "Female"),
        ("1", "Male")
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, verbose_name="user")
    profile_photo = models.ImageField(upload_to=get_unique_filename, default="default/user.svg", verbose_name="profile photo")
    gender = models.CharField(max_length=1, choices=GENDER, blank=True, verbose_name="gender")
    role = models.ForeignKey(Role, on_delete=models.SET(get_delete_role), verbose_name="role")


    class Meta:
        verbose_name = "user profile"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.user.username
    

class UserFileManager(models.Manager):
    def get_queryset(self) -> QuerySet:
        return super().get_queryset().filter(file_cate="0")


class UserDirManager(models.Manager):
    def get_queryset(self) -> QuerySet:
        return super().get_queryset().filter(file_cate="1")
    

class MessageManager(models.Manager):
    def get_queryset(self) -> QuerySet:
        return super().get_queryset().filter(action="0")
    

class ApprovalManager(models.Manager):
    def get_queryset(self) -> QuerySet:
        return super().get_queryset().filter(action="1")
    

class FileType(BaseModel):
    type_name = models.CharField(max_length=50, verbose_name="type name")
    suffix = models.CharField(unique=True, blank=True, max_length=10, verbose_name="suffix")

    class Meta:
        verbose_name = "File type"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.suffix
    
class UserFile(BaseModel):
    CATEGORY = [
        ("0", "document"),
        ("1", "folder")
    ]

    DELETE_FLAGS = [
        ("0", "not assembled"),
        ("1", "recycled")
    ]

    create_by = models.ForeignKey(User, on_delete=models.SET(get_delete_user), related_name="files",
                                  blank=True, null=True, verbose_name="creator")
    
    file_name = models.CharField(max_length=100, verbose_name="file name")
    file_uuid = models.UUIDField(unique=True, default=get_uuid, verbose_name="file number")
    file_cate = models.CharField(choices=CATEGORY, max_length=1, verbose_name="file classification")
    file_type = models.ForeignKey(FileType, blank=True, null=True, on_delete=models.SET(get_delete_file_type),
                                  verbose_name="file type")
    file_size = models.BigIntegerField(default=0, verbose_name="file size")
    file_path = models.CharField(db_index=True, max_length=500, verbose_name="file path")
    folder = models.ForeignKey("self", on_delete=models.CASCADE, to_field="file_uuid",
                               null=True, blank=True, verbose_name="improved catalog")
    delete_flag = models.CharField(max_length=1, default="0", choices=DELETE_FLAGS, verbose_name="logo")


    class Meta:
        ordering = ["-create_time"]
        verbose_name = "user file"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.file_name
    

class FileAgent(UserFile):
    objects = UserFileManager()

    class Meta:
        proxy = True
        verbose_name = "file agent"
        verbose_name_plural = verbose_name

class UserDir(UserFile):
    objects = UserDirManager()

    class Meta:
        proxy = True
        verbose_name = "user folder"
        verbose_name_plural = verbose_name


class FileShare(BaseModel):
    create_by = None

    secret_key = models.CharField(db_index=True, max_length=10, verbose_name = "share key")
    signature = models.CharField(max_length=70, verbose_name="e-signature")
    user_file = models.ForeignKey(UserFile, on_delete=models.CASCADE, verbose_name="document")
    expire_time = models.DateTimeField(verbose_name="best before date")
    summary = models.CharField(blank=True, max_length=100, verbose_name="share other description")


    class Meta:
        ordering = ["-create_time"]
        verbose_name = "General file"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.user_file.file_name
    
class ShareRecord(BaseModel):
    create_by = None

    file_share = models.ForeignKey(FileShare, on_delete=models.SET(get_delete_file_share),
                                   verbose_name= "General file")
    recipient = models.ForeignKey(User, null=True, on_delete=models.SET(get_delete_user), 
                                  verbose_name="recipient")
    anonymous = models.GenericIPAddressField(null=True, blank=True, verbose_name="anonymous user")

    class Meta:
        verbose_name = "time to get file"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.file_share.user_file.file_name
    

class Notice(BaseModel):
    title = models.CharField(max_length=50, verbose_name="signature")
    content = models.TextField(verbose_name="notice message")


    class Meta:
        verbose_name = "notice"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.title
    

class Message(BaseModel):
    ACTION = [
        ("0", "message"),
        ("1", "statement")
    ]

    STATE = [
        ("0", "unconfirmed"),
        ("1", "accepted"),
        ("2", "unsuccessful")
    ]

    action = models.CharField(max_length=1, choices=ACTION, verbose_name="type")
    state = models.CharField(max_length=1, default="0", choices=STATE, verbose_name="state")
    content = models.TextField(verbose_name="text message")

    class Meta:
        verbose_name = "message"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.create_by.username
    
class UserMessage(Message):
    objects = MessageManager()

    class Meta:
        proxy = True
        verbose_name = "user message"
        verbose_name_plural = verbose_name


class UserApproval(Message):
    object = ApprovalManager()

    class Meta:
        proxy = True
        verbose_name = "user app"
        verbose_name_plural = verbose_name

    
class UserLog(models.Model):
    ACTION = [
        ("0", "sign in"),
        ("1", "compose"),
        ("2", "login error")
    ]

    username = models.CharField(max_length=128, verbose_name="user name")
    ip_address = models.GenericIPAddressField(verbose_name="IP-address")
    browser = models.CharField(max_length=200, verbose_name="browser")
    os = models.CharField(max_length=30, verbose_name="os")
    action = models.CharField(max_length=1, choices=ACTION, verbose_name="action")
    msg = models.CharField(max_length=100, verbose_name="data")
    action_time = models.DateTimeField(auto_now_add=True, verbose_name="time")

    class Meta:
        verbose_name = "user action journey"
        verbose_name_plural = verbose_name

    def __str__(self) -> str:
        return self.ip_address