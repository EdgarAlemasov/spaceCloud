from django import forms
from django.contrib.auth.validators import UnicodeUsernameValidator


class UserBaseForm(forms.Form):
    username = forms.CharField(max_length=150, validators=(UnicodeUsernameValidator,))
    password = forms.CharField(min_length=6 ,max_length=128)
    remember = forms.BooleanField(required=False)


class InfoForm(forms.Form):
    GENDER = [
        ("0", "Female"),
        ("1", "Male")
    ]


    gender = forms.ChoiceField(choices=GENDER)
    email = forms.EmailField(required=False)


class PasswordForm(forms.Form):
    old_password = forms.CharField(min_length=6, max_length=150)
    new_password = forms.CharField(min_length=6, max_length=150)


class AvatarForm(forms.Form):
    avatar = forms.ImageField()