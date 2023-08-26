from django.apps import AppConfig


class CloudConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cloud'
    verbose_name = "space cloud"


    def ready(self) -> None:
        return
