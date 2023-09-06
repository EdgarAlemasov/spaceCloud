# mycloud
Мой дипломный проект  


### Запуск локально
___
1. Установка зависимостей
```
pip install -r requirements.txt
```
2. Проверьте файл конфигурации, измените конфигурацию почтового ящика и базы данных
```
# mycloud/settings.py


EMAIL_HOST = 'localhost'
EMAIL_PORT = '25'
EMAIL_HOST_USER = '**********'
EMAIL_HOST_PASSWORD = '********'
EMAIL_USE_TLS = False
DEFAULT_FROM_EMAIL = 'myspacecloud@localhost'


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'spacecloud',
        'HOST': '127.0.0.1',
        'PORT': '5432',
        'USER': '***',
        'PASSWORD': '******',
    }
}
```
3. Перенос базы данных
```
python manage.py migrate
```
4. Запустите базовый sql-файл
```
mysql> use cloud;
mysql> source C:/Users/..../.sql; 
```
5. Создайте суперпользователя
```
python manage.py createsuperuser
```
6. Запустите локальный сервер
```
python manage.py runserver
```