# sniffer_core.py

import socket

def get_ip_from_url(url):
    """
    Преобразует URL в IP-адрес.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    host = url.split("/")[0].split(":")[0]
    if not host:
        raise ValueError("Invalid URL: no host found")
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host: {host}") from e


def parse_filters(filters_str):
    """
    Парсит строку фильтров в список ключевых слов.
    """
    if not filters_str:
        return []
    return [kw.strip() for kw in filters_str.split("\n") if kw.strip()]


def should_display_line(line, filters, use_filters, invert_filters):
    """
    Определяет, должна ли строка быть отображена с учётом фильтров.
    """
    if not use_filters or not filters:
        return True

    contains_keyword = any(kw in line for kw in filters)
    if invert_filters:
        return not contains_keyword
    else:
        return contains_keyword