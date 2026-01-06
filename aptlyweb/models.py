from django.db import models

# Define models to be saved in the SQL Database here

# helper not in DB to define Aptly Permissions
class Repository(models.Model):
    class Meta:
        managed = False  # No database table creation or deletion operations will be performed for this model. 
        default_permissions = () # disable "add", "change", "delete" and "view" default permissions
        permissions = [
            # Repository Permissions
            ("can_create_repos", "Can create repositories"),
            ("can_edit_repos", "Can edit repositories"),
            ("can_delete_repos", "Can delete repositories"),
            ("can_upload_repos", "Can upload packages to repository"),
            ("can_remove_repos", "Can remove packages from repository"),
        ]

# helper not in DB to define Aptly Permissions
class Snapshot(models.Model):
    class Meta:
        managed = False  # No database table creation or deletion operations will be performed for this model. 
        default_permissions = () # disable "add", "change", "delete" and "view" default permissions
        permissions = [
            # Snapshot Permissions
            ("can_create_snapshots", "Can create snapshots"),
            ("can_edit_snapshots", "Can edit snapshots"),
            ("can_delete_snapshots", "Can delete snapshots"),
        ]


# helper not in DB to define Aptly Permissions
class Published(models.Model):
    class Meta:
        managed = False  # No database table creation or deletion operations will be performed for this model. 
        default_permissions = () # disable "add", "change", "delete" and "view" default permissions
        permissions = [
             # APT_Repository Permissions
            ("can_create_APT_repositories", "Can create published APT_repositories"),
            ("can_edit_APT_repositories", "Can edit published APT_repositories"),
            ("can_delete_APT_repositories", "Can delete published APT_repositories"),
        ]
