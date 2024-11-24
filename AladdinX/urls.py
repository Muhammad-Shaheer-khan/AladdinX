from django.urls import path
# from email_analysis.views import IndexView
from email_analysis.views import *
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    path('api/analyze-header/', analyze_header, name='analyze-header'),
]
