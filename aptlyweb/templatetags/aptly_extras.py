from django import template

from aptly_api.client import PublishAPISection

register = template.Library()

@register.filter
def splitws(value):
    """Split on any whitespace; returns a list of parts."""
    if value is None:
        return []
    return str(value).split() 

@register.filter
def escape_prefix(value):
    """Escape aptly prefix to be used in URL."""
    if value is None:
        value = "."
    return PublishAPISection.escape_prefix(value)