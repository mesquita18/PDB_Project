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
    return dictionary.get(key)

@register.filter
def none_to_zero(value):
    return 0.0 if value is None else value
