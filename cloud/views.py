from datetime import timedelta
import json
from pathlib import Path
from shutil import rmtree, move as file_move
from typing import Any, Dict
from uuid import UUID


from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.core.signing import Signer, TimestampSigner, BadSignature, SignatureExpired
from django.core.mail import send_mail
from django.http import FileResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils import timezone
from django.views.generic import View, TemplateView, RedirectView
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from .forms import UserBaseForm, InfoForm, AvatarForm, PasswordForm
from .models import (UserFile, FileAgent, UserDir, FileShare, ShareRecord,
                     FileType, UserApproval, UserMessage, Notice)
from .paginations import NoticeResultSetPagination
from .serializers import FileSerializer, FileShareSerializer, FolderSerializer, NoticeSerializer
from .utils import AjaxObj, get_key_signature, get_dir_size, make_archive_bytes, file_size_format


# first page
class StartPageView(TemplateView):
    template_name = "cloud/start_page.html"

# cloud disk
class CloudDiskView(TemplateView):
    template_name = "cloud/cloud_disk.html"

# history
class HistoryView(TemplateView):
    template_name = "cloud/history.html"

# backet
class BacketView(TemplateView):
    template_name = "cloud/backet.html"

# file information
class FileInfoView(TemplateView):
    template_name = "cloud/file_info.html"

# Personal Information 
class UserPageView(LoginRequiredMixin, TemplateView):
    template_name = "cloud/user_page.html"

    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        context = super().get_context_data()
        role = self.request.user.profile.role.role_ley
        if role == "common":
            context["applied"] = UserApproval.object.filter(create_by=self.request.user)
        context.update({
            "role": role,
            "record": UserApproval.object.filter(create_by=self.request.user),
            "message": UserApproval.object.filter(create_by=self.request.user)
        })
        return context
    
# link to get common files
class ShareLinkView(TemplateView):
    template_name = "cloud/share.html"

    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        signature = self.kwargs.get("signature", None)
        context = super().get_context_data()
        try:
            share = FileShare.objects.select_related("user_file").get(secret_key=Signer().unsign(signature))
        except (BadSignature, FileShare.DoesNotExist):
            context["expired"] = True
        else:
            expired = timezone.now() > share.expire_time
            if not expired:
                if self.request.user.is_authenticated:
                    ShareRecord.objects.create(file_share=share, recipient=self.request.user)
                else:
                    ShareRecord.objects.create(file_share=share, anonymous=self.request.META.get("REMOTE_ADDR", None))
                context,update({
                    "file": share.user_file,
                    "share": share
                })
            context["expired"] = expired
        return context
    
# Result reset password
class ResetPasswordDoneView(TemplateView):
    template_name = "cloud/reset_password_done.html"

    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        param = self.kwargs.get("param", None)
        context = super().get_context_data()
        try:
            auth = TimestampSigner().unsign_object(param, max_age=settings.TOKEN_EXPIRY)
            if auth.get("token", "") != settings.RESET_TOKEN:
                context["auth"] = False
            else:
                user = User.objects.get(user_name=auth.get("user", ""))
                user.set_password(settings.RESET_PASSWORD)
                user.save()
                context["auth"] = True
        except (BadSignature, SignatureExpired):
            context["auth"] = False
        return context