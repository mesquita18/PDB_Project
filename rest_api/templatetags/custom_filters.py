from django import template
register = template.Library()
@register.filter
def periodo_ordinal(value):
    try:
        value = int(value)
    except (ValueError, TypeError):
        return value
    if 10 <= value % 100 <= 20:
        return f"{value}°"
    suffix = {1: "°", 2: "°", 3: "°"}.get(value % 10, "°")
    return f"{value}{suffix}"

@register.filter
def get_item(dictionary, key):
    try:
        # Support dict-like and objects; be defensive for None
        if dictionary is None:
            return None
        if hasattr(dictionary, 'get'):
            return dictionary.get(key)
        return getattr(dictionary, key, None)
    except Exception:
        return None


@register.filter
def dict_get(obj, key):
    """Return a value from a dict or attribute from an object, fallback to empty string."""
    try:
        if obj is None:
            return ""
        if isinstance(obj, dict):
            return obj.get(key, "")
        return getattr(obj, key, "")
    except Exception:
        return ""

@register.filter
def none_to_zero(value):
    return 0.0 if value is None else value
