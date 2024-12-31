from django import template
register = template.Library()
@register.filter
def periodo_ordinal(value):
    try:
        value = int(value)
    except (ValueError, TypeError):
        return value

    # Definindo o sufixo
    if 10 <= value % 100 <= 20:
        return f"{value}°"
    suffix = {1: "°", 2: "°", 3: "°"}.get(value % 10, "°")
    
    return f"{value}{suffix}"