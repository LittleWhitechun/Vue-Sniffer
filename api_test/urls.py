from django.conf.urls import url, include
from .views import *

urlpatterns = [
    url(r'get_packet$', get_packet, ),
    url(r'get_device$', get_device, )
]