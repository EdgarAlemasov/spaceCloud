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
from django.views.decorators.csrf import csrf_exempt
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
                context.update({
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
    
class LoginView(View):
    @csrf_exempt
    def post(self, request):
        form = UserBaseForm(request.POST)
        if form.is_valid():
            user = authenticate(request, username = form.cleaned_data["user_name"],
                                password = form.cleaned_data["password"])
            if user:
                login(request, user)
                if not form.cleaned_data["remember"]:
                    request.session.set_expiry(0)
                return AjaxObj(msg="SUCCESSFUL LOGIN", data=request.session["cloud"]).get_responce()
            return AjaxObj(400, "ERROR", {"errors": {
                "user_name": ["wrong login or password"]
            }}).get_responce()
        return AjaxObj(400, "ERROR", {"errors": form.errors}).get_responce()
    

class RegisterView(View):
    @csrf_exempt
    def post(self, request):
        form = UserBaseForm(request.POST)
        if form.is_valid():
            if User.objects.filter(user_name=form.cleaned_data["user_name"]).exists():
                return AjaxObj(400, "ERROR", {"errors": {"user_name": ["User name already exsist"]}}).get_responce()
            User.objects.create_user(user_name=form.cleaned_data["user_name"],
                                     password=form.cleaned_data["password"])
            return AjaxObj(msg="SUCCESSFUL REGISTRATION").get_responce()
        return AjaxObj(400, "ERROR", {"errors": form.errors}).get_responce()
    
class LoginOutView(RedirectView):
    pattern_name = "cloud:start_page"

    def get(self, request, *args, **kwargs):
        logout(request)
        return super().get(request, *args, **kwargs)
    

class AlterAvatarView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        form = AvatarForm(request.POST, request.FILES)
        if form.is_valid():
            if form.changed_data["avatar"].size > settings.MAX_AVATAR_SIZE:
                return AjaxObj(400, f"Upload image too high, size can't higher then {file_size_format(settings.MAX_AVATAR_SIZE)}").get_responce()
            profile = request.user.profile
            profile.avatar = form.changed_data["avatar"]
            profile.update_by = request.user
            profile.save()
            return AjaxObj(msg="SUCCESSFUL UPLOAD").get_responce()
        return AjaxObj(400, "Forbidden files").get_responce()
    

class AlterPasswordView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        form = PasswordForm(request.POST)
        if form.is_valid():
            if request.user.check_password(form.changed_data["old_password"]):
                request.user.set_password(form.cleaned_data["new_password"])
                request.user.save()
                return AjaxObj(msg="Password was changed").get_responce()
            return AjaxObj(400, "ERROR", {"errors": {"old_password": ["password is not correct"]}}).get_responce()
        return AjaxObj(400, "ERROR", {"errors": form.errors}).get_responce()
    


class ResetPasswordView(View):
    @csrf_exempt
    def post(self, request):
        user_name = request.POST.get("resetName").strip()
        queryset = User.objects.filter(user_name=user_name)

        if not queryset.exists():
            return AjaxObj(400, "ERROR", {"errors": { "resetName": ["User name does not exist"]}}).get_responce()
        
        user = queryset.get()
        if user.email == "":
            return AjaxObj(400, "ERROR", {"errors": {"resetName": ["User does not related with email"]}}).get_responce()
        
        auth = {"user": user.user_name, "token": settings.RESET_TOKEN}
        context = {
            "scheme": request.MEAT.get("wsgi.url_scheme"),
            "host": request.META.get("HTTP_HOST"),
            "param": TimestampSigner().sign_object(auth),
            "password": settings.RESET_PASSWORD
        }

        html = render_to_string("cloud/reset.html", context)
        send_mail(
            subject="Tiny Cloud",
            message=html,
            from_email=None,
            recipient_list=[user.email],
            fail_silently=True,
            html_message=html
        )

        return AjaxObj(msg="Message has been sent").get_responce()
    

class AlterInfoView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        form = InfoForm(request.POST)

        if not form.is_valid():
            return AjaxObj(400, "ERROR", {"errors": form.errors}).get_responce()
        user = request.user
        profile = user.profile
        email = form.changed_data["email"]
        gender = form.cleaned_data["gender"]

        if email != "" and User.objects.filter(email=email).exclude(user_name=user.user_name).exists():
            return AjaxObj(400, "ERROR", {"errors": {"email": ["User already related profile with email"]}}).get_responce()
        
        profile.gender = gender
        profile.update_by = user
        user.email = email
        profile.save()
        user.save()
        return AjaxObj(msg="Changing was successful").get_responce()
    

class MsgApprView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        message = request.POST.get("message").strip()
        if not message:
            return AjaxObj(400, "Forbidden information").get_responce()
        if request.POST.get("way") == "apply":
            msg = "Successfully submitted application"
            UserApproval.objects.create(content=message, create_by=request.user)
        else:
            msg = "Thank you for request"
            UserApproval.objects.create(context=message, create_by=request.user)
        return AjaxObj(200, msg=msg).get_responce()
    

class FileBlobView(View):

    def get(self, request, *args, **kwargs):
        uuid = self.kwargs.get("uuid")
        blob = self.request.GET.get("blob")
        root = settings.MEDIA_ROOT

        try:
            file = UserFile.objects.get(file_uuid=uuid)
        except UserFile.DoesNotExist:
            return AjaxObj(400, "File does not exist").get_responce()
        
        if file.file_cate == "0":
            response = FileResponse(open(root / file.file_path, "rb"), as_attachment=True)
            if blob: response.as_attachment = False
            return response
        else:
            return FileResponse(make_archive_bytes(root / file/file_path), as_attachment=True, file_name = "cloud.zip")
        

class DuplicateCheck(LoginRequiredMixin, View):

    def get(self, request, *args, **kwargs):
        folder = request.user.files.get(file_uuid=request.GET.get("folderUUID", request.session["root"]))
        path = Path(folder.file_path) / request.GET.get("uploadName")

        if (Path(settings.MEDIA_ROOT) / path).exists():
            return AjaxObj(400, "Folder is already exsist. Please, attention to the backet").get_responce()
        
        return AjaxObj.get_responce()
    

class FileUploadView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        file = request.FILES.get("file")
        if not file:
            return AjaxObj().get_responce()
        use = request.session["cloud"]["used"] + file.size
        if use > request.session["cloud"]["storage"]:
            return AjaxObj(400, "Not enough memory").get_responce()
        
        folder = request.user.files.get(file_uuid=request.POST.get("folderUUID", request.session["root"]))
        file_path = Path(folder.file_path) / file.name
        file_type = FileType.objects.get_or_create(suffix=Path(file.name).suffix,
                                                   defaults={"type_name": "undefined"})[0]
        dirs = list()

        with open(settings.MEDIA_ROOT / file_path, "wb") as f:
            for chunk in file.chunks():
                f.write(chunk)
        
        FileAgent(file_name=file.name, file_type=file_type, file_size=file.size, file_path=file_path,
                  folder=folder, create_by=request.user).save()
        

        while folder:
            folder.file_size = folder.file_size + file.size
            folder.update_by = request.user
            dirs.append(folder)
            folder = folder.folder
        
        UserDir.objects.bulk_update(dirs, ("file_size", "update_by"))
        request.session["cloud"]["used"] = use
        return AjaxObj(200, "File has been upload").get_responce()
    
class FolderUploadView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        files = request.FILES.getlist("files")
        paths = request.POST.getlist("paths")

        if not files or not paths: return AjaxObj().get_responce()

        path_nums = len(paths)
        if path_nums * 2 > settings.DATA_UPLOAD_MAX_NUMBER_FIELDS:
            return AjaxObj(400, f"Files count can't more then {settings.DATA_UPLOAD_MAX_NUMBER_FIELDS}").get_responce()
        
        use = request.session["cloud"]["used"] + sum(s.size for s in files)
        if use > request.session["cloud"]["storage"]:
            return AjaxObj(400, "Not enough memory").get_responce()
        
        folder = request.user.files.get(file_uuid=request.POST.get("folderUUID", request.session["root"]))
        folder_path = Path(folder.file_path)
        objs, dirs = list(), list()

        for i in range(path_nums):
            parts = Path(paths[i]).parts[:-1]
            temp_folder = folder
            temp_path = folder_path
            for path in parts:
                part_path = temp_path / parts
                if Path(settings.MEDIA_ROOT / part_path).exists():
                    prev = UserDir.objects.get(file_path=part_path)
                    temp_folder = prev
                    temp_path = Path(part_path)
                else:
                    prev = UserDir(file_name=part, file_path=part_path, folder=temp_folder, create_by=request.user)
                    dirs.append(prev)
                    prev.save()
                    Path.mkdir(settings.MEDIA_ROOT / part_path)
                    temp_folder = prev
                    temp_path = Path(part_path)

            file = files[i]
            file_path = temp_path / file.name
            with open(settings.MEDIA_ROOT / file_path, "wb") as f:
                for chunk in file.chunks():
                    f.write(chunk)
            file_type = FileType.objects.get_or_create(suffix=Path(file.name).suffix,
                                                       defaults={"type_name": "неизвестный"})[0]
            objs.append(UserFile(file_name=file.name, file_cate="0", file_type=file_type, file_size=file.size,
                                 file_path=file_path, folder=temp_folder, create_by=request.user))

        for d in dirs:
            d.file_size = get_dir_size(settings.MEDIA_ROOT / d.file_path)
            d.update_by = request.user

        while folder is not None:
            folder.file_size = get_dir_size(settings.MEDIA_ROOT / folder_path)
            folder.update_by = request.user
            dirs.append(folder)
            folder = folder.folder
            folder_path = folder.file_path if folder is not None else None

        FileAgent.objects.bulk_create(objs)
        UserDir.objects.bulk_update(dirs, ("file_size", "update_by"))

        request.session["cloud"]["used"] = use
        return AjaxObj(200, "Folder has been added successfully").get_responce()
    

class ShareCreateView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        uuid = request.POST.get("uuid")
        while True:
            key, signature = get_key_signature()
            if not FileShare.objects.filter(secret_key=key).exists():
                break

        share = FileShare.objects.create(secret_key=key, signature=signature,
                                         user_file=UserFile.objects.get(file_uuid=uuid),
                                         expire_time=timezone.now() + timedelta(days=7))
        return AjaxObj(200, data={"key": key, "signature": signature, "id": share.id}).get_responce()


class ShareUpdateView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        data = json_loads(request.body)
        share = FileShare.objects.get(id=data.get("id"))
        delta = data.get("delta")
        summary = data.get("summary")
        if delta is None and summary is not None:
            share.summary = summary
        elif delta is not None and summary is None:
            share.expire_time = timezone.now() + timedelta(days=delta)
        else:
            share.summary = summary
            share.expire_time = timezone.now() + timedelta(days=delta if delta is not None else 0)
        share.update_by = request.user
        share.save()
        return AjaxObj(200, "Link has been set successfully").get_responce()


class ShareGetView(View):
    @csrf_exempt
    def post(self, request):
        key = request.POST.get("key")
        try:
            share = FileShare.objects.select_related("user_file").get(secret_key=key)
        except FileShare.DoesNotExist:
            return AjaxObj(400, "Password expired").get_responce()

        if timezone.now() > share.expire_time:
            return AjaxObj(400, "Password expired").get_responce()
        file = share.user_file
        if request.user.is_authenticated:
            ShareRecord.objects.create(file_share=share, recipient=request.user)
        else:
            ShareRecord.objects.create(file_share=share, anonymous=request.META.get("REMOTE_ADDR"))
        return AjaxObj(200, data={
            "file": {"name": file.file_name, "size": file.file_size, "uuid": file.file_uuid},
            "share": {"expire": share.expire_time, "summary": share.summary}
        }).get_responce()


class ShareDelete(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        ids = json_loads(request.body).get("ids")
        for i in ids:
            try:
                FileShare.objects.select_related("user_file").filter(
                    user_file__create_by=request.user).get(id=i).delete()
            except FileShare.DoesNotExist:
                return AjaxObj(400, "The record contains files that do not exist or have been deleted").get_responce()
        return AjaxObj(200, "record successfully deleted").get_responce()


class FileMoveView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        data = json_loads(request.body)
        if data.get("src") == data.get("dst"):
            return AjaxObj(400, "Empty folder").get_responce()

        src = request.user.files.get(file_uuid=data.get("src"))
        dst = request.user.files.get(file_uuid=data.get("dst", request.session["root"]))

        if request.user.files.filter(folder=dst, file_cate=src.file_cate, file_name=src.file_name).exists():
            return AjaxObj(400, "The folder has file with this name").get_responce()

        dirs = list()
        src_folder = src.folder

        file_move(str(settings.MEDIA_ROOT / src.file_path), str(settings.MEDIA_ROOT / dst.file_path))
        src.folder = dst
        src.file_path = Path(dst.file_path) / src.file_name
        src.update_by = request.user
        src.save()

        # Обновите папку назначения и исходную папку, а также размер ее родительской папки
        # (за исключением корневого каталога)
        while dst.folder is not None:
            dst.file_size = dst.file_size + src.file_size
            dst.update_by = request.user
            dirs.append(dst)
            dst = dst.folder
        while src_folder.folder is not None:
            src_folder.file_size = src_folder.file_size - src.file_size
            src_folder.update_by = request.user
            dirs.append(src_folder)
            src_folder = src_folder.folder

        if not dirs:
            UserDir.objects.bulk_update(dirs, ("file_size", "update_by"))

        return AjaxObj(200, "Успешное перемещение папки").get_responce()


class FileDeleteView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        uuids = json_loads(request.body).get("uuids")
        use = request.session["cloud"]["used"]
        code = msg = folder = None
        discard = 0
        dirs = list()
        for uuid in uuids:
            try:
                file = request.user.files.get(file_uuid=uuid)
                discard += file.file_size
                if not folder:
                    folder = file.folder
            except UserFile.DoesNotExist:
                break
            real_path = settings.MEDIA_ROOT / file.file_path
            if file.file_cate == "0":
                real_path.unlink()
            else:
                rmtree(real_path)
            file.delete()
        else:
            code, msg = 200, "Delete has been successfully"
        if not code and not msg:
            code, msg = 400, "Some files don't exist or has been deleted"

        while folder is not None:
            folder.file_size = folder.file_size - discard
            folder.update_by = request.user
            dirs.append(folder)
            folder = folder.folder
        if not dirs:
            UserDir.objects.bulk_update(dirs, ("file_size", "update_by"))

        use -= discard
        request.session["cloud"]["used"] = use

        return AjaxObj(code, msg).get_responce()


class FileTrashView(LoginRequiredMixin, View):
    @csrf_exempt
    def post(self, request):
        json_data = json_loads(request.body)
        method = json_data.get("method")
        uuids = json_data.get("uuids")
        objs = list()
        if method == "trash":
            del_flag = "1"
            msg = "Delete has been successfully"
        else:
            del_flag = "0"
            msg = "Recovery has been successfully"
        for uuid in uuids:
            try:
                file = request.user.files.get(file_uuid=uuid)
            except UserFile.DoesNotExist:
                return AjaxObj(400, "Some files don't exist or has been deleted").get_responce()
            file.del_flag = del_flag
            file.update_by = request.user
            objs.append(file)

        UserFile.objects.bulk_update(objs, ("del_flag",))
        return AjaxObj(200, msg).get_responce()


class CloudViewSet(ModelViewSet):

    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None

    def get_queryset(self):
        folder_uuid = self.request.query_params.get("folderUUID", self.request.session["root"])
        sort = self.request.query_params.get("sort")
        order = self.request.query_params.get("order")
        search = self.request.query_params.get("search")

        if search:
            queryset = self.request.user.files.filter(file_name__icontains=search, file_cate="0", del_flag="0")
        else:
            queryset = self.request.user.files.select_related("folder").filter(folder__file_uuid=folder_uuid,
                                                                               del_flag="0")
        if sort:
            queryset = queryset.order_by(sort)
            if order == "desc":
                queryset = queryset.order_by("-" + sort)
        return queryset


class HistoryViewSet(ModelViewSet):

    serializer_class = FileShareSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        sort = self.request.query_params.get("sort")
        order = self.request.query_params.get("order")
        search = self.request.query_params.get("search")
        queryset = FileShare.objects.select_related("user_file").filter(user_file__create_by=self.request.user)

        if search:
            queryset = queryset.filter(user_file__file_name__icontains=search)
        if sort:
            queryset = queryset.order_by(sort)
            if order == "desc":
                queryset = queryset.order_by("-" + sort)
        return queryset


class BinViewSet(ModelViewSet):

    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        sort = self.request.query_params.get("sort")
        order = self.request.query_params.get("order")
        search = self.request.query_params.get("search")
        queryset = self.request.user.files.filter(del_flag="1")

        if search:
            queryset = queryset.filter(file_name__icontains=search)
        if sort:
            queryset = queryset.order_by(sort)
            if order == "desc":
                queryset = queryset.order_by("-" + sort)
        return queryset


class FolderViewSet(ModelViewSet):

    serializer_class = FolderSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None

    def get_queryset(self):
        exclude = self.request.query_params.get("exclude")
        folder_uuid = self.request.query_params.get("folderUUID", self.request.session["root"])
        return self.request.user.files.select_related("folder").filter(folder__file_uuid=folder_uuid,
                                                                       file_cate="1",
                                                                       del_flag="0").exclude(file_uuid=exclude)


class FileViewSet(ModelViewSet):

    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None

    def get_queryset(self):
        try:
            uuid = UUID(hex=self.request.query_params.get("uuid"))
        except ValueError:
            return UserFile.objects.none()
        return self.request.user.files.filter(file_uuid=uuid, file_cate="0")


class NoticeViewSet(ModelViewSet):

    serializer_class = NoticeSerializer
    queryset = Notice.objects.all()
    permission_classes = [IsAuthenticated]
    pagination_class = NoticeResultSetPagination


def bad_request_view(request, exception, template_name="errors/400.html"):
    return render(request, template_name, status=400)


def permission_denied_view(request, exception, template_name="errors/403.html"):
    return render(request, template_name, status=403)


def not_found_view(request, exception, template_name="errors/404.html"):
    return render(request, template_name, status=404)


def server_error_view(request, template_name="errors/500.html"):
    return render(request, template_name, status=500)
