import os
import hmac
import uuid
import secrets
import zipfile
from io import BytesIO
from pathlib import Path

from django.core.signing import Signer
from django.utils import timezone, dateformat
from django.http import JsonResponse


def get_uuid():
    return memoryview(uuid.uuid1().bytes)[:32].hex()


def get_key_signature():
    secret_key = secrets.token_hex(3)
    signature = Signer.sign(secret_key)
    return secret_key, signature


def get_secret_path(values: bytes):
    h = hmac.new(secrets.token_bytes(3), values, "sha1")
    return h.hexdigest()


def get_unique_filename(instance, file_name):
    return f"uploads/{dateformat.format(timezone.localdate(), 'Y/m/d')}/{get_uuid()}{Path(file_name).suffix}"


def get_dir_size(path):
    return sum(f.stat().st_size for f in path.glob("**/*") if f.is_file())


def make_archive_bytes(dir_path):
    buffer = BytesIO()
    dl = len(str(dir_path.parent)) + 1

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipper:
        for basedir, subdir, files in os.walk(dir_path):
            base = Path(basedir)
            parent = Path(basedir[dl:])
            zipper.writestr(str(parent) + "/", "")
            for file in files:
                zipper.write(base / file, parent / file)
            for folder in subdir:
                zipper.writestr(str(parent / folder) + "/", "")

    
    buffer.seek(0)
    return buffer

def file_size_format(value, fixed=2):
    if value < 1024: size = f"{value}B"
    elif value < 1048579: size = f"{round(value / 1024, fixed)}KB"
    elif value < 1073741824: size = f"{round(value / 1024 / 1024, fixed)}MB"
    else: size = f"{round(value / 1024 / 1024 /1024, fixed)}GB"
    return size


class AjaxObj(dict):
    def __init__(self, code=200, msg="", data=None):
        if data is None: data = dict()
        super(AjaxObj, self).__init__()
        self.update(code=code, msg=msg, data=data)

    def set_data(self, **kwargs):
        self["data"].update(**kwargs)

    def set_result(self, result):
        if not isinstance(result, list):
            raise TypeError(f"result should be list type not a {type(result)}")
        self["data"]["result"] = result

    def set_errors(self, errors):
        if not isinstance(errors, dict):
            raise TypeError(f"errors should be dict type not a {type(errors)}")
        self["data"]["errors"] = errors

    def get_responce(self):
        return JsonResponse({
            "code": self["code"],
            "msg": self["msg"],
            "data": self["data"]
        }) 
