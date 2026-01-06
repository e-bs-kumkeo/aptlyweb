# aptlyweb/views.py Request-Handling Functions to Render Pages

import re
from typing import List, Dict, Any, NamedTuple, Sequence
import os, shutil, subprocess
import tempfile
from django.http import Http404
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib import messages
from django.utils import timezone
from django.utils.http import urlencode

from requests.auth import HTTPBasicAuth
from aptly_api import Client, Package
from environs import env
import urllib3


from .forms import LoginForm, PublishUpdateForm, RepoCreateForm, RepoRemoveForm, RepoUploadForm, SigningForm, SnapshotCreateForm, PublishForm, RepoEditForm, SnapEditForm, SOURCE_LOCAL, SOURCE_SNAP, SourceFormSet

# helper function so we raise errors if wrongly configured
def getClient() -> Client: 
    if not getClient.client:
        APTLY_API_URL = env.str("APTLY_API_URL")
        ssl_verify = not env.bool("APTLY_API_SKIP_SSL", False)
        if not ssl_verify:
            # silence warning
            urllib3.disable_warnings()
        # authentication
        basic = None
        if env.str("APTLY_API_USERNAME", None) is not None:
            user = env.str("APTLY_API_USERNAME")
            pw = None
            if env.str("APTLY_API_PASSWORD_FILE", default=None):
                path = env.str("APTLY_API_PASSWORD_FILE")
                with open(path, 'r') as file:
                    pw = file.read()
            elif env.str("APTLY_API_PASSWORD", default=None):
                pw = env.str("APTLY_API_PASSWORD")
            # neither password or file given
            if not pw:
                raise RuntimeError("no api password given, use APTLY_API_PASSWORD or APTLY_API_PASSWORD_FILE environment variables")
            basic = HTTPBasicAuth(user, pw)
        # initializing the client
        getClient.client = Client(aptly_server_url=APTLY_API_URL, ssl_verify=ssl_verify, http_auth=basic)
    return getClient.client
# set the "static" for the function
getClient.client = None

# helper function so we raise errors if wrongly configured
def getURL() -> str: 
    if not getURL.url:
        getURL.url = env.str("APTLY_URL")
    return getURL.url
# set the "static" for the function
getURL.url = None

# AptlyWeb views

# Example Template for Development (view in browser at URL/template/)
def template(request):
    return render(request, "aptlyweb/template_base_material.html")

###############################################################################################################################################
# MARK: home
###############################################################################################################################################


# Homepage accessed at URL/home/
def home(request):
    api = getClient()
    repositories = api.repos.list()
    snapshots = api.snapshots.list()
    endpoints = api.publish.list()
    return render(request, "aptlyweb/home.html", {"repositories": repositories, "snapshots": snapshots, "endpoints": endpoints, "url": getURL()},)

###############################################################################################################################################
# MARK: login
###############################################################################################################################################

# Login view
def login_user(request):
    form = LoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        if "login_submit" in request.POST:
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("home")
            else:
                messages.error(request, "invalid username or password")
                return redirect("login")
      
    return render(request, "aptlyweb/login.html", {"form": form})     

# Logout view
def logout_user(request):
    logout(request)
    messages.success(request, "You have been logged out")
    return redirect("login")

###############################################################################################################################################
# MARK: published view
###############################################################################################################################################

# Calls all Publishes and renders the published.html
def published(request):
    api = getClient()
    endpoints = api.publish.list()
    return render(request, "aptlyweb/published.html", {"endpoints": endpoints, "url": getURL()})

# Calls a Published Version and renders its Detail page published_detail.html with a query search
def published_detail(request, prefix: str, distribution: str):
    clean_prefix = parse_escaped_prefix(prefix)

    api = getClient()
    endpoint = getPublishedRepo(api, clean_prefix, distribution)
    if not endpoint:
        raise Http404(f"Endpoint with prefix='{clean_prefix}' and distribution='{distribution}' not found")

    return render(request, "aptlyweb/published_detail.html", {"endpoint": endpoint, "debOneline": debOneLine(endpoint, getURL()), 'deb822': deb822(endpoint, getURL())})

# Calls a Published Version and renders its Detail page published_detail.html with a query search
@login_required
@permission_required("aptlyweb.can_create_APT_repositories", raise_exception=True)
def published_update(request, prefix: str, distribution: str):
    clean_prefix = parse_escaped_prefix(prefix)
    api = getClient()

    signing_form = SigningForm(request.POST or None)

    if request.method == "POST":
        form = PublishUpdateForm(request.POST or None)

        if form.is_valid() & signing_form.is_valid():
            source_kind = form.cleaned_data['source_kind']
            force_overwrite = form.cleaned_data['force_overwrite']

            if source_kind == "local":
                api.publish.update(
                    prefix=clean_prefix, 
                    distribution=distribution, 
                    force_overwrite=force_overwrite,
                    **getSigningOptions(signing_form) # double splat, to convert dict to kwargs
                ) 
                messages.success(request, "Published repository updated")
                return redirect("published_detail", prefix=prefix, distribution=distribution )
            else:
                messages.error(request, "Snapshot update not supported currently")


    endpoint = getPublishedRepo(api, clean_prefix, distribution)
    if not endpoint:
        raise Http404(f"Endpoint with prefix='{clean_prefix}' and distribution='{distribution}' not found")
    
    if request.method != "POST":
        form = PublishUpdateForm(initial={"source_kind": endpoint.source_kind})

    return render(request, "aptlyweb/published_update.html", {"endpoint": endpoint, "form": form, "signing_form": signing_form})

# Function to Add a new Publish, renders published_add.html and handles the Request-Form
@login_required
@permission_required("aptlyweb.can_create_APT_repositories", raise_exception=True)
def published_add(request):
    source_kind = request.GET.get('source_kind')
    # default to local
    if not source_kind in [SOURCE_LOCAL, SOURCE_SNAP]:
        source_kind = SOURCE_LOCAL

    api = getClient()
    form = PublishForm(request.POST or None)
    signing_form = SigningForm(request.POST or None)
    formset = None

    if request.method == "POST":
        formset = SourceFormSet(request.POST)
    else:
        sources = []
        if source_kind == SOURCE_SNAP:
            snaps = api.snapshots.list()
            for snap in snaps:
                sources.append({
                    "name": snap.name,
                    "component": "", # requires APTLY >= 1.6.0
                }) 
        else:
            repos = api.repos.list()
            for repo in repos:
                sources.append({
                    "name": repo.name,
                    "component": repo.default_component,
                }) 
        formset = SourceFormSet(initial=sources)

    if request.method == "POST":
        # use bitwise and & to avoid short-circuit evaluation
        if form.is_valid() & formset.is_valid() & signing_form.is_valid():
            try:
                endpoint = publish_from_form(
                    form=form,
                    api=api,
                    source_formset=formset,
                    source_kind=source_kind,
                    signing_form=signing_form,
                )
                messages.success(request,f"Repository published ({endpoint.prefix} / {endpoint.distribution})")
                return redirect("published_detail", prefix=api.publish.escape_prefix(endpoint.prefix), distribution=endpoint.distribution )
            except Exception as e:
                messages.error(request, str(e))

    return render(request, "aptlyweb/published_add.html",
        {
            "form": form,
            "signing_form": signing_form,
            "source_formset": formset,
            "source_kind": source_kind,
        },
    )

# Function to Delete a Publish, does not render a new page, see published.html to see the JavaScript implementation, handles the Request-Form
@login_required
@permission_required("aptlyweb.can_delete_APT_repositories", raise_exception=True)
def published_delete(request):
    if request.method != "POST":
        messages.error(request, "invalid request")
        return redirect("published")

    prefix_from_post = request.POST.get("prefix", "").strip()
    distribution_from_post = request.POST.get("distribution", "").strip()

    try:
        api = getClient()
        if hasattr(api.publish, "drop"):
            api.publish.drop(prefix=prefix_from_post, distribution=distribution_from_post)
    except Exception as exc:
        messages.error(request, f"deletion error: {exc}")
        return redirect("published")

    messages.success(request, f"APT Repository with prefix: '{prefix_from_post}' and distribution: '{distribution_from_post}'  was deleted")
    return redirect("published")

###############################################################################################################################################
# MARK: repository view
###############################################################################################################################################

# Calls all Repositories and renders the repositories.html
def repositories(request):
    api = getClient()
    output = api.repos.list()
    return render(request, "aptlyweb/repositories.html", {"repositories": output})

# Calls a Repository and renders its Detail page repository_detail.html
def repository_detail(request, repository_name):
    api = getClient()
    if not repository_name:
        raise Http404("missing repository_name")
    repository_detail = api.repos.show(repository_name)
    packages = preparePackageList(api.repos.search_packages(repository_name))
    return render(request, "aptlyweb/repository_detail.html", {"repository": repository_detail, "packages": packages})


# Function to Add a new Repository, renders repository_add.html and handles the Request-Form
@login_required
@permission_required("aptlyweb.can_create_APT_repositories", raise_exception=True)
def repository_add(request):

    api = getClient()

    snap_names = get_snapshots(api)
    form = RepoCreateForm(request.POST or None, snap_choices=snap_names)


    if request.method == "POST" and form.is_valid():
        name = form.cleaned_data["name"].strip()
        comment = (form.cleaned_data.get("comment") or "").strip() or None
        dist = (form.cleaned_data.get("default_distribution") or "").strip() or None
        comp = (form.cleaned_data.get("default_component") or "").strip() or None

        try:
            if not form.cleaned_data["snap_name"]:
                api.repos.create(
                    reponame=name,
                    comment=comment,
                    default_distribution=dist,
                    default_component=comp,
                )
                messages.success(request, f"Repository '{name}' was created")
                return redirect("repository_detail", name)

            else:
                # from Snapshot
                chosen = form.cleaned_data["snap_name"]  

                package_keys = []
                pkgs = api.snapshots.list_packages(chosen, detailed=True)
                package_keys.extend([_pkg_key(p) for p in pkgs])
                package_keys = _dedup([k for k in package_keys if k])

                if not comment:
                    now = timezone.now().strftime("%Y-%m-%d %H:%M")
                    comment = f"Created from snapshot: {chosen} — {now}"

                if name != "/":
                    api.repos.create(
                        reponame=name,
                        comment=comment,
                        default_distribution=dist,
                        default_component=comp,
                    )
                    messages.success( request, f"Repository '{name}' was created from snapshot with {len(package_keys)} package(s)" )

                if package_keys:
                    CHUNK = 1000
                    for i in range(0, len(package_keys), CHUNK):
                        api.repos.add_packages_by_key(name, *package_keys[i:i+CHUNK])


                return redirect("repository_detail", name)

        except Exception as exc:
                messages.error(request, str(exc))
            # fallthrough

    return render(request, "aptlyweb/repository_add.html",
        {
            "snap_names": snap_names,
            "form": form,
        },
    )

# Function to upload a package to a tepository, renders repository_upload.html and handles the Request-Form,
@login_required
@permission_required("aptlyweb.can_upload_repos", raise_exception=True)
def repository_upload(request, repository_name):
    upload_form = RepoUploadForm(request.POST or None, request.FILES)
    api = getClient()

    # if request.method == "POST" and upload_form.is_valid():
    if request.method == "POST":
        if not upload_form.is_valid():
            messages.error(request, f"{upload_form.errors}")
        else:
            with tempfile.TemporaryDirectory(prefix="aw_") as tmpdirname:
                files: list[str] = []
                #files = request.FILES["file"]
                for fieldName in request.FILES:
                    file = request.FILES[fieldName]
                    
                    files.append(f"{tmpdirname}/{file.name}")
                    with open(files[-1], "wb+") as destination:
                        for chunk in file.chunks():
                            destination.write(chunk)

                try:
                    uploadDir = tmpdirname.removeprefix("/tmp/")
                    api.files.upload(uploadDir, *files)

                    force_replace = upload_form.cleaned_data.get("force_replace") or False
                    api.repos.add_uploaded_file(reponame=repository_name, dir=uploadDir, force_replace=force_replace)

                    messages.success(request, f"Files uploaded.")
                    return redirect("repository_detail", repository_name)
                except Exception as exc:
                    messages.error(request, f"{exc}")

    repo = api.repos.show(repository_name)
    return render(request, "aptlyweb/repository_upload.html", {"repo": repo})

# Function to remove a package from a tepository, handles the Request-Form and redirects to repository_detail.html
@login_required
@permission_required("aptlyweb.can_upload_repos", raise_exception=True)
def repository_remove(request, repository_name):
    remove_form = RepoRemoveForm(request.POST or None)
    api = getClient()
    # if request.method == "POST" and upload_form.is_valid():
    if request.method == "POST":
        if not remove_form.is_valid():
            messages.error(request, f"{remove_form.errors}")
        else:
            try:
                key = str(remove_form.cleaned_data.get("package_key"))
                api.repos.delete_packages_by_key(repository_name, key)
                messages.success(request, "Package removed")
            except Exception as exc:
                messages.error(request, f"{exc}")
    return redirect("repository_detail", repository_name)

# Function to Delete a Repository, does not render a new page, see repositories.html to see the JavaScript implementation, handles the Request-Form
@login_required
@permission_required("aptlyweb.can_delete_repos", raise_exception=True)
def repository_delete(request, name=None):
    if request.method != "POST":
        messages.error(request, "invalid request")
        return redirect("repositories")

    name_from_post = request.POST.get("repository_name", "").strip()
    name_to_delete = (name or "").strip() or name_from_post

    try:
        api = getClient()
        if hasattr(api.repos, "delete"):
            api.repos.delete(name_to_delete)
    except Exception as exc:
        messages.error(request, f"deletion error: {exc}")
        return redirect("repositories")

    messages.success(request, f"Repository '{name_to_delete}' was deleted")
    return redirect("repositories")

# Function to Edit a Repository, renders repository_edit.html and handles the Request-Form, ! RENAMING NOT AS INTENDED, NOT USED !
@login_required
@permission_required("aptlyweb.can_edit_repos", raise_exception=True)
def repository_edit(request, repository_name):

    api = getClient()

    if request.method == "POST":
        repo_form = RepoEditForm(request.POST)
        if repo_form.is_valid():
            #old = repo_form.cleaned_data["repository_name"]
            new = (repo_form.cleaned_data.get("name") or "").strip()
            comment = repo_form.cleaned_data.get("comment") or None
            dist    = repo_form.cleaned_data.get("distribution") or None
            comp    = repo_form.cleaned_data.get("component") or None

            target = repository_name

            if not repo_form.errors:
                try:
                    if any(x is not None for x in (comment, dist, comp)):
                        api.repos.edit(
                            reponame=target,
                            comment=comment,
                            default_distribution=dist,
                            default_component=comp,
                        )
                    messages.success(request, f"Repository ‘{repository_name}’ was updated.")
                    return redirect("repository_detail", target)
                except Exception as exc:
                    messages.error(request, str(exc))

    repo = api.repos.show(reponame=repository_name)._asdict()
    if request.method != "POST":
        repo_form = RepoEditForm(initial=repo)

    return render(request, "aptlyweb/repository_edit.html", {"repo": repo, "form": repo_form})

###############################################################################################################################################
# MARK: snapshot views
###############################################################################################################################################

# Calls all Snapshots and renders the snapshots.html
def snapshots(request):
    api = getClient()
    output = api.snapshots.list()
    return render(request, "aptlyweb/snapshots.html", {"snapshots": output})

# Calls a Snapshot and renders its Detail page snapshot_detail.html
def snapshot_detail(request, snapshot_name):
    api = getClient()
    if not snapshot_name:
        raise Http404("missing snapshot_name")
    snapshot_detail = api.snapshots.show(snapshot_name)
    packages = preparePackageList(api.snapshots.list_packages(snapshot_name))
    return render(request, "aptlyweb/snapshot_detail.html", {"snapshot": snapshot_detail, "packages": packages})

# Function to Add a new Sapshot, renders snapshot_add.html and handles the Request-Form
@login_required
@permission_required("aptlyweb.can_create_snapshots", raise_exception=True)
def snapshot_add(request):

    api = getClient()
    repo_names = get_repositories(api)
    snap_form = SnapshotCreateForm(request.POST or None, repo_choices=repo_names)

    if request.method == "POST" and snap_form.is_valid():
        sdata = snap_form.cleaned_data

        create_args = {
            "reponame": sdata.get("repo_name"),
            "snapshotname": sdata.get("name", ""),
            "description": sdata.get("description", ""),
        }
        reponame = sdata.get("repo_name")
        snapshotname = sdata.get("name", "")
        description = sdata.get("description", "")

        def create(reponame, snapshotname, description):
            if reponame:
                # create from repo
                return api.snapshots.create_from_repo(reponame=reponame,snapshotname=snapshotname,description=description)
            else:
                # create empty
                return api.snapshots.create_from_packages(snapshotname=snapshotname,description=description)

        try:
            snapshot = create(reponame=reponame,snapshotname=snapshotname,description=description)
            # snapshot created
            messages.success(request, f"Snapshot '{snapshotname}' created successfully")
            return redirect("snapshot_detail", snapshotname)
        except Exception as exc:
            messages.error(request, str(exc))
        
    return render(request, "aptlyweb/snapshot_add.html", {
        "repo_names": repo_names,
        "form": snap_form
    })

# Function to Delete a Snapshot, does not render a new page, see snapshots.html to see the JavaScript implementation, handles the Request-Form
@login_required
@permission_required("aptlyweb.can_delete_snapshots", raise_exception=True)
def snapshot_delete(request, name=None):
    if request.method != "POST":
        messages.error(request, "invalid request")
        return redirect("snapshots")

    name_from_post = request.POST.get("snapshot_name", "").strip()
    name_to_delete = (name or "").strip() or name_from_post

    try:
        api = getClient()
        if hasattr(api.snapshots, "delete"):
            api.snapshots.delete(name_to_delete)
    except Exception as exc:
        messages.error(request, f"deletion error: {exc}")
        return redirect("snapshots")

    messages.success(request, f"Snapshot '{name_to_delete}' was deleted")
    return redirect("snapshots")

# Function to Edit a Snapshot, renders snapshot_edit.html and handles the Request-Form
@login_required
@permission_required("aptlyweb.can_edit_snapshots", raise_exception=True)
def snapshot_edit(request, snapshot_name):
    
    api = getClient()
    snap = api.snapshots.show(snapshot_name)._asdict()
    snap_form = SnapEditForm(request.POST or None, initial=snap)

    if request.method == "POST" and snap_form.is_valid():
        newname = snap_form.cleaned_data.get("snapshot_newname") or None
        newdesc = snap_form.cleaned_data.get("snapshot_newdescription") or None
        try:
            api.snapshots.update(
                snapshotname=snapshot_name,
                newname=newname,
                newdescription=newdesc,
            )
            messages.success(request, f"Snapshot '{snapshot_name}' was edited")
            return redirect("snapshot_detail", newname or snapshot_name)
        except Exception as exc:
            messages.error(request, str(exc))

    return render(request, "aptlyweb/snapshot_edit.html", {"snap": snap, "form": snap_form})


###############################################################################################################################################
# MARK: package views
###############################################################################################################################################

# Calls a Package and renders its Detail page package_detail.html
def package_detail(request, key):
    api = getClient()
    if not key:
        raise Http404("missing package key")
    details = api.packages.show(key)
    return render(request, "aptlyweb/package_detail.html", {"pkg": details})

###############################################################################################################################################
# MARK: helper functions
###############################################################################################################################################


# Getting Data from the Aptly API
def get_repositories(api: Client) -> list[str]:
    try:
        repo_objs = api.repos.list()
        repo_names = [getattr(r, "name", None) or getattr(r, "Name", None) or (r.get("Name") if isinstance(r, dict) else None) for r in repo_objs]
        repo_names = [r for r in repo_names if r]
    except Exception:
        repo_names = []
    return repo_names

def get_snapshots(api: Client) -> list[str]:
    try:
        snap_objs = api.snapshots.list()
        snap_names = [getattr(s, "name", None) or getattr(s, "Name", None) or (s.get("Name") if isinstance(s, dict) else None) for s in snap_objs]
        snap_names = [s for s in snap_names if s]
    except Exception:
        snap_names = []
    return snap_names

# helper for pre 1.6.0 aptly
# TODO remove once we updated to 1.6.0
def getPublishedRepo(api: Client, prefix: str, distribution: str):
    # TODO when moving to aptly >= 1.6 use publish show
    endpoints = api.publish.list()

    def matches(ep):
        p = getattr(ep, "prefix", None) if hasattr(ep, "prefix") else (ep.get("prefix") if isinstance(ep, dict) else None)
        d = getattr(ep, "distribution", None) if hasattr(ep, "distribution") else (
            ep.get("distribution") or ep.get("Distribution") if isinstance(ep, dict) else None
        )
        if p is None or d is None:
            return False
        return str(p).rstrip("/") == prefix and str(d) == distribution

    return next((e for e in endpoints if matches(e)), None)

# Package Key Information
def _pkg_key(key) -> str | None:
    return getattr(key, "key", None) or getattr(key, "Key", None) or (key.get("Key") if isinstance(key, dict) else None)

def _dedup(seq):
    return list(dict.fromkeys(seq))

def parse_escaped_prefix(prefix: str) -> str:
    if prefix == ":.":
        return "."
    return prefix.replace("_", "/").replace("//", "_")

# create old one line deb sources format
def debOneLine(endpoint, url):
    comps = ' '.join(str(src['Component']) for src in endpoint.sources)
    return f"deb [trusted=yes] { url }/{ endpoint.prefix } {endpoint.distribution} {comps}"

# create new source format (since trixie)
def deb822(endpoint, url):
    comps = ' '.join(str(src['Component']) for src in endpoint.sources)
    return f"Types: deb\nTrusted: yes\nURIs: {url}/{ endpoint.prefix }\nSuites: { endpoint.distribution }\nComponents: {comps}"

# Helper Function to Publish a Release from a Request-Form
def publish_from_form(*, form, api: Client, source_formset, source_kind: str, signing_form: SigningForm) -> Any:                        

    prefix = form.cleaned_data["publish_prefix"]
    distribution = form.cleaned_data["distribution"]

    architectures = form.cleaned_data.get("architectures")

    label = form.cleaned_data.get("label") or None
    origin = form.cleaned_data.get("origin") or None

    sources = []

    for f in source_formset: 
        cd = f.cleaned_data
        if cd.get('enabled'):
            sources.append({
                "Name": cd.get('name'),
                "Component": cd.get('component'),
            })
    

    endpoint = api.publish.publish(
        source_kind=source_kind,        
        sources=sources,
        architectures=architectures,      
        prefix=prefix,
        distribution=distribution,
        label=label,
        origin=origin,
        force_overwrite=False,           
        acquire_by_hash=None,
        **getSigningOptions(signing_form), # double splat, to convert dict to kwargs
    )
    return endpoint

def getSigningOptions(form: SigningForm) -> Any:
    sign_skip = form.cleaned_data['sign_skip']

    opts = {
        'sign_skip': sign_skip,
        'sign_batch': True, # workaround for pre 1.6.0 versions. Otherwise the User must enter the password on the server
    }

    if not sign_skip:
        opts['sign_gpgkey'] = form.cleaned_data['gpg_key'] or None
        opts['sign_keyring'] = form.cleaned_data['gpg_keyring'] or None
        opts['sign_passphrase'] = form.cleaned_data['passphrase'] or None
        opts['sign_passphrase_file'] = form.cleaned_data['passphrase_file'] or None
    
    return opts


class DisplayPackage(NamedTuple):
    key: str
    name: str
    arch: str
    version: str
    files_hash: str

# the key have the form '<prefix>P<arch> <package> <version> <hash>'
packageRegex = re.compile(r'^(?P<prefix>\S*)P(?P<arch>\S+)\s(?P<package>\S+)\s(?P<version>\S+)\s(?P<hash>\S+)$')
# sort and clear 
def preparePackageList(pkgs: Sequence[Package]) -> Sequence[DisplayPackage]:
    prepared: List[DisplayPackage] = []
    for pkg in pkgs:
        m = packageRegex.match(pkg.key)
        if m:
            group = m.groupdict() 
            prepared.append(DisplayPackage(key=pkg.key, name=group['package'], arch=group['arch'], version=group['version'], files_hash=group['hash']))

    prepared.sort(key = lambda p: (p.name, p.version, p.arch))
    
    return prepared
