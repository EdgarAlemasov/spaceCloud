from django.urls import path
from rest_framework.routers import DefaultRouter


from cloud import views

app_name = "cloud"

# main pages
urlpatterns = [
    path("", views.StartPageView.as_view(), name="start_page"),
    path("user_page", views.UserPageView.as_view(), name="user_page"),
    path("cloud_disk", views.CloudDiskView.as_view(), name="cloud_disk"),
    path("history", views.HistoryView.as_view(), name="history"),
    path("backet",  views.BacketView.as_view(), name="backet"),
    path("file_info", views.FileInfoView.as_view(), name="file_info"),
]


# share pages
urlpatterns += [
    path("share-get", views.ShareGetView.as_view(), name="share-get"),
    path("share-create", views.ShareCreateView.as_view(), name="share-create"),
    path("share-update", views.ShareUpdateView.as_view(), name="share-update"),
    path("history-delete", views.ShareDelete.as_view(), name="history-delete"),
    path("share/<str:signature>", views.ShareLinkView.as_view(), name="share-link"),
]


# document pages
urlpatterns += [
    path("file-blob/<uuid:uuid>", views.FileBlobView.as_view(), name="file-blob"),
    path("file-delete", views.FileDeleteView.as_view(), name="file_delete"),
    path("file-upload", views.FileUploadView.as_view(), name="file-upload"),
    path("file-trash", views.FileTrashView.as_view(), name="file-trash"),
    path("file-move", views.FileMoveView.as_view(), name="file-move"),
    path("folder-upload", views.FolderUploadView.as_view(), name="folder-upload"),
    path("duplicated-check", views.DuplicateCheck.as_view(), name="duplicated-check"),
]


# authorization
urlpatterns += [
    path("login", views.LoginView.as_view(), name="login"),
    path("register", views.RegisterView.as_view(), name="register"),
    path("logout", views.LoginOutView.as_view(), name="logout"),
    path("reset-password", views.ResetPasswordView.as_view(), name="reset-password"),
    path("reset-done/<str:param>", views.ResetPasswordDoneView.as_view(), name="reset-done"),
]


# personal information
urlpatterns += [
    path("alter-avatar", views.AlterAvatarView.as_view(), name="alter-avatar"),
    path("alter-password", views.AlterPasswordView.as_view(), name="alter-password"),
    path("alter-info", views.AlterInfoView.as_view(), name="alter-info"),
    path("msg-appr", views.MsgApprView.as_view(), name="message"),
]


# resful api
router = DefaultRouter(trailing_slash=False)
router.register("cloud", views.CloudViewSet, "api-cloud")
router.register("history", views.HistoryViewSet, "api-history")
router.register("backet", views.BinViewSet, "api-backet")
router.register("folder", views.FolderViewSet, "api-folder")
router.register("file", views.FileViewSet, "api-file")
router.register("notice", views.NoticeViewSet, "api-notice")
