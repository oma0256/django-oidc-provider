try:
    from django.contrib.auth.views import (
        LogoutView, LoginView
    )
except ImportError:
    from oidc_provider.compat import (
        LogoutView, LoginView
    )
try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    url(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^accounts/login/$', LoginView.as_view(template_name='login.html'), name='login'),
    url(r'^accounts/logout/$', LogoutView.as_view(next_page='/'), name='logout'),
    url(r'^', include('oidc_provider.urls', namespace='oidc_provider')),
    url(r'^admin/', admin.site.urls),
]
