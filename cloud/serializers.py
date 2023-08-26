from rest_framework import serializers
from .models import UserFile, FileShare, Notice


class FileSerializer(serializers.ModelSerializer):
    file_type = serializers.StringRelatedField()
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M")

    class Meta:
        model = UserFile
        fields = [
            "id",
            "file_name",
            "file_uuid",
            "file_cate",
            "file_type",
            "file_size",
            "create_time"
        ]


class FileShareSerializer(serializers.ModelSerializer):
    user_file = serializers.StringRelatedField()
    expire_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M")
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M")


    class Meta:
        model = FileShare
        fields = [
            "id",
            "secret_key",
            "signature",
            "user_file",
            "expire_time",
            "create_time",
            "summary"
        ]


class FolderSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFile
        fields = [
            "file_name",
            "file_uuid"
        ]

class NoticeSerializer(serializers.ModelSerializer):
    create_by = serializers.StringRelatedField()
    create_time = serializers.DateTimeField(format="%Y-%m-%d")

    class Meta:
        model = Notice
        fields = [
            "title",
            "content",
            "create_by",
            "create_time"
        ]