from django.urls import path

from . import views

# Define the AptlyWeb URLs here

urlpatterns = [ 
    path("", views.home, name="home"),
    path("home/", views.home, name="home"),
    path("login_user/", views.login_user, name="login"),
    path("logout_user/", views.logout_user, name="logout"),
    path("template/", views.template, name="template"),
    path("published/", views.published, name="published"),
    path("published/add/", views.published_add, name="published_add"),
    path("published/delete/", views.published_delete, name="published_delete"),
    path("published/<str:prefix>/<str:distribution>", views.published_detail, name="published_detail"),
    path("published/<str:prefix>/<str:distribution>/update", views.published_update, name="published_update"),
    path("repositories/", views.repositories, name="repositories"),
    path("repositories/delete/", views.repository_delete, name="repository_delete"),
    path("repositories/add/", views.repository_add, name="repository_add"),
    path("repositories/<str:repository_name>/", views.repository_detail, name="repository_detail"),
    path("repositories/<str:repository_name>/edit/", views.repository_edit, name="repository_edit"),
    path("repositories/<str:repository_name>/upload/", views.repository_upload, name="repository_upload"),
    path("repositories/<str:repository_name>/remove/", views.repository_remove, name="repository_remove"),
    path("snapshots/", views.snapshots, name="snapshots"),
    path("snapshots/delete/", views.snapshot_delete, name="snapshot_delete"),
    path("snapshots/add/", views.snapshot_add, name="snapshot_add"),
    path("snapshots/<str:snapshot_name>/", views.snapshot_detail, name="snapshot_detail"),
    path("snapshots/<str:snapshot_name>/edit/", views.snapshot_edit, name="snapshot_edit"),
    path("package/<str:key>/", views.package_detail, name="package_detail"),
]
