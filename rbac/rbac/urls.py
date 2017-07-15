"""rbac URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

from django.conf.urls import include, url
from django.contrib import admin

from auth.api import views_api_resource


urlpatterns = [
    url(r'^admin/', admin.site.urls),

    url(r'^(?P<version>(v1))/(?P<namespace>(main))/auth/',
        include([
            url(r'^register_project/$',
                views_api_resource.ProjectRegistrationView.as_view(),
                name='register_projects_list'),

        ])),

    url(r'^(?P<version>(v1))/(?P<namespace>(main))/auth/',
        include([

            url(r'^projects/(?P<project_name>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='projects_detail'),
            url(r'^projects/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='projects_list'),

        ])),

    url(
        r'^(?P<version>(v1))/(?P<namespace>(main))/auth/projects/(?P<project_name>[^/]+)/',
        include([

            url(r'^groups/(?P<pk>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='groups_detail'),
            url(r'^groups/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='groups_list'),

            url(r'^groups/(?P<groups_pk>[^/]+)/users/(?P<users_pk>[^/]+)/$',
                views_api_resource.AddRemoveResourceView.as_view(),
                name='add_remove_groups_users'),
            url(r'^groups/(?P<groups_pk>[^/]+)/certificate_users/(?P<certificate_users_pk>[^/]+)/$',
                views_api_resource.AddRemoveResourceView.as_view(),
                name='add_remove_groups_certificate_users'),
            url(r'^roles/(?P<groups_pk>[^/]+)/groups/(?P<roles_pk>[^/]+)/$',
                views_api_resource.AddRemoveResourceView.as_view(),
                name='add_remove_groups_roles'),

            url(r'^users/(?P<pk>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='users_detail'),
            url(r'^users/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='users_list'),
            url(r'^users/(?P<pk>[^/]+)/password/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='changepassword_detail'),

            url(r'^ldap_config/(?P<pk>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='ldap_config_detail'),
            url(r'^ldap_config/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='ldap_config_list'),

            url(r'^certificate_users/(?P<pk>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='certificate_users_detail'),
            url(r'^certificate_users/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='certificate_users_list'),

            url(r'^tokens/$',
                views_api_resource.AuthTokenResourceView.as_view(),
                name='tokens_details'),
            url(r'^permissions/$',
                views_api_resource.CheckResourcePermissionView.as_view(),
                name='permissions_details'),

            url(r'^roles/(?P<pk>[^/]+)/$',
                views_api_resource.GenericRetrieveUpdateDestroyResourceView.as_view(),
                name='roles_detail'),
            url(r'^roles/$',
                views_api_resource.GenericListCreateResourceView.as_view(),
                name='roles_list'),

            url(r'^roles/(?P<roles_pk>[^/]+)/rules/$',
                views_api_resource.AddRemoveChangeRuleView.as_view(),
                name='add_remove_roles_rules'),
            url(r'^roles/(?P<roles_pk>[^/]+)/rules/(?P<rules_pk>[^/]+)/$',
                views_api_resource.AddRemoveChangeRuleView.as_view(),
                name='add_remove_roles_rules'),
            url(r'^roles/(?P<roles_pk>[^/]+)/rules/(?P<rules_pk>[^/]+)/orders/(?P<orders_no>[^/]+)/$',
                views_api_resource.AddRemoveChangeRuleView.as_view(),
                name='add_remove_roles_rules'),

        ])),
]
