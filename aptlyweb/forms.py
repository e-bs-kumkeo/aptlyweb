from django import forms
from django.core import validators

# Define Request-Forms here

SOURCE_LOCAL = "local"
SOURCE_SNAP = "snapshot"
SOURCE_KINDS = [(SOURCE_LOCAL, "Local Repository"), (SOURCE_SNAP, "Snapshot")]

class LoginForm(forms.Form):
    username = forms.CharField(label="Username", required=True)
    password = forms.CharField(label="Password", widget=forms.PasswordInput, required=True)

class SlugField(forms.CharField):
    default_validators = [validators.validate_slug]

class RepoCreateForm(forms.Form):
    name = SlugField(label="Name", max_length=200, required=True)
    comment = forms.CharField(label="Comment", required=False)
    default_distribution = forms.CharField(label="Default Distribution", required=False)
    default_component = forms.CharField(label="Default Component", required=False)
    snap_name = forms.ChoiceField(label="From Snapshot", required=False)

    def __init__(self, *args, snap_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        snap_choices = snap_choices or []
         # TODO when using Aptly 1.6.0+ allow empty again
        # choices = [("", "— create empty snapshot —")] + [(r, r) for r in repo_choices]
        choices = [("", "— Create Empty Repository —")] + [(r, r) for r in snap_choices]
        self.fields["snap_name"].choices = choices


class SnapshotCreateForm(forms.Form):
    name = SlugField(label="Name (Required)", max_length=255, required=True)
    description = forms.CharField(label="Description", required=False)
    # TODO when using Aptly 1.6.0+ allow empty again
    # repo_name = forms.ChoiceField(label="From Repository", required=False)
    repo_name = forms.ChoiceField(label="From Repository", required=True)

    def __init__(self, *args, repo_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        repo_choices = repo_choices or []
         # TODO when using Aptly 1.6.0+ allow empty again
        # choices = [("", "— create empty snapshot —")] + [(r, r) for r in repo_choices]
        choices = [("", "— Select Repository —")] + [(r, r) for r in repo_choices]
        self.fields["repo_name"].choices = choices

# for comma seperated values
class MultiValueField(forms.Field):
    def to_python(self, value):
        """Normalize data to a list of strings."""
        # Return an empty list if no input was given.
        if not value:
            return []
        return [s.strip() for s in value.split(",")]
    
class SourceForm(forms.Form):
    enabled = forms.BooleanField(label="Enabled", required=False)
    name = forms.CharField(label="Name", widget=forms.HiddenInput)
    component = forms.CharField(label="Component", max_length=32, required=False)

    def clean(self):
        """Checks that component has a value if enabled."""
        if self.cleaned_data.get("enabled"):
            comp = self.cleaned_data.get("component")
            if not comp:
                self.add_error("component", "Please define component name")

class BaseSourceFormSet(forms.BaseFormSet):
    def clean(self):
        """Checks that at least one source is enabled."""
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
         
        enabled = 0
        for form in self.forms:
            enabled = enabled + form.cleaned_data.get("enabled")
        if enabled == 0:
            raise forms.ValidationError("At least one source required")

SourceFormSet = forms.formset_factory(SourceForm, formset=BaseSourceFormSet, extra=0)

class SigningForm(forms.Form):
    template_name = "aptlyweb/material_forms/signing.html"

    sign_skip = forms.BooleanField(label="Skip Signing",required=False, initial=True)

    gpg_key = forms.CharField(label="GPG Key to use", required=False, help_text="Leave blank to use default GPG key")
    gpg_keyring = forms.CharField(label="GPG Keyring to use", required=False, help_text="Leave blank to use default GPG keyring")
    passphrase = forms.CharField(label="GPG Passphrase", widget=forms.PasswordInput, required=False, help_text="Passphrase to unlock given GPG key")
    passphrase_file = forms.CharField(label="GPG Passphrase file on Server", required=False, help_text="Path to passphrase file on the server")

    def clean(self):
        super().clean()

        skip = self.cleaned_data.get("sign_skip") 
        if skip:
            return 
        
        pp = self.cleaned_data.get("passphrase")
        pf = self.cleaned_data.get("passphrase_file")

        if pp and pf:
            self.add_error("passphrase", "Can't use both passphrase and passphrase file")
            self.add_error("passphrase_file", "Can't use both passphrase and passphrase file")

        if not pp and not pf:
            self.add_error(None, "Must supply either passphrase or passphrase file when signing")



class PublishForm(forms.Form):
    publish_prefix = forms.CharField(label="Prefix", required=True, max_length=255)
    distribution = forms.CharField(label="Distribution", required=True, max_length=255)
    architectures = MultiValueField(label="Architectures", required=False, help_text="Leave empty to include all architectures, seperate architectures with comma")
    # label = forms.CharField(label="label", required=False)
    # origin = forms.CharField(label="origin", required=False)

    def clean_publish_prefix(self):
        val = (self.cleaned_data.get("publish_prefix") or "").strip()
        if val.startswith("/"):
            raise forms.ValidationError("'/' is not allowed as a leading character")
        return val

class RepoEditForm(forms.Form):
    name = forms.CharField(label="Name", required=False, disabled=True)
    comment = forms.CharField(label="Comment", required=False)
    distribution = forms.CharField(label="Distribution", required=False)
    component = forms.CharField(label="Component", required=False)

    def clean_repository_newname(self):
        val = (self.cleaned_data.get("name") or "").strip()
        if "/" in val:
            raise forms.ValidationError("'/' is not allowed to use")
        return val


class SnapEditForm(forms.Form):
    name = forms.CharField(label="Name", required=False)
    description = forms.CharField(label="Description", required=False)

    def clean(self):
        super().clean()
        if not self.changed_data:
            self.add_error(None, "At least one field must change")

# debian package upload form
class RepoUploadForm(forms.Form):
    force_replace = forms.BooleanField(label="Force Replace", required=False, initial=False)
    debfile = forms.FileField(label="File to Upload", required=True)

# remove package from repository form
class RepoRemoveForm(forms.Form):
    package_key = forms.CharField(label="Package Key", required=True)
        
class PublishUpdateForm(forms.Form):
    source_kind = forms.ChoiceField(choices=SOURCE_KINDS, widget=forms.HiddenInput, required=True)
    force_overwrite = forms.BooleanField(label="Force Overwrite", initial=False, required=False)

