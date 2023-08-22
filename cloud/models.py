from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

# from .utils import get_uuid, get_unique_filename

def get_delete_user():
    return User.objects.get_or_create(username="anonymous", defaults={
        "password": "anonymous"
    })[0]

# Create your models here.
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
    