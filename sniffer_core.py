# sniffer_core.py

import socket
import re
import sys
import os
import ctypes
from urllib.parse import urlparse
from typing import Tuple, Optional, List
import logging

logger = logging.getLogger(__name__)


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Проверяет корректность URL.
    Возвращает (True, "") если URL валиден, иначе (False, "сообщение об ошибке")
    """
    if not url:
        return False, "URL не может быть пустым"
    
    if not isinstance(url, str):
        return False, "URL должен быть строкой"
    
    url = url.strip()
    
    # Добавляем схему если отсутствует
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = urlparse(url)
        # Проверяем наличие схемы и netloc
        if not all([result.scheme, result.netloc]):
            return False, "Некорректный формат URL"
        
        # Проверяем схему
        if result.scheme not in ('http', 'https'):
            return False, "URL должен начинаться с http:// или https://"
        
        # Убираем порт для проверки домена
        domain = result.netloc.split(':')[0]
        
        if not domain:
            return False, "Не указан домен"
        
        # Базовая проверка домена
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        # Разрешаем IP-адреса и доменные имена
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        if not (domain_pattern.match(domain) or ip_pattern.match(domain)):
            return False, "Некорректное доменное имя или IP-адрес"
        
        # Проверяем IP-адрес на валидность октетов
        if ip_pattern.match(domain):
            octets = domain.split('.')
            for octet in octets:
                if int(octet) > 255:
                    return False, "Некорректный IP-адрес"
        
        return True, ""
    except Exception as e:
        return False, f"Ошибка при разборе URL: {str(e)}"


def is_admin() -> bool:
    """
    Проверяет, запущен ли скрипт с правами администратора.
    """
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def safe_request(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Безопасный HTTP GET запрос с обработкой всех исключений.
    
    Args:
        url: URL для запроса
        timeout: таймаут в секундах
    
    Returns:
        Tuple[success: bool, status_code: Optional[int], message: str]
    """
    try:
        import requests
        from requests.exceptions import (
            ConnectionError,
            Timeout,
            HTTPError,
            RequestException,
            SSLError,
            TooManyRedirects
        )
    except ImportError:
        return False, None, "Библиотека requests не установлена"
    
    # Добавляем схему если отсутствует
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return True, response.status_code, f"Успешно: {response.status_code}"
    
    except Timeout:
        error_msg = f"Превышено время ожидания при подключении к {url}"
        logger.error(error_msg)
        return False, None, error_msg
    
    except ConnectionError as e:
        error_msg = f"Ошибка подключения к {url}: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg
    
    except SSLError as e:
        error_msg = f"Ошибка SSL сертификата для {url}: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg
    
    except TooManyRedirects:
        error_msg = f"Слишком много перенаправлений для {url}"
        logger.error(error_msg)
        return False, None, error_msg
    
    except HTTPError as e:
        error_msg = f"HTTP ошибка {e.response.status_code} для {url}"
        logger.error(error_msg)
        return False, e.response.status_code, error_msg
    
    except RequestException as e:
        error_msg = f"Ошибка запроса к {url}: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg
    
    except Exception as e:
        error_msg = f"Неожиданная ошибка при запросе к {url}: {str(e)}"
        logger.exception(error_msg)
        return False, None, error_msg


def check_sniff_permissions() -> Tuple[bool, str]:
    """
    Проверяет возможность захвата пакетов.
    
    Returns:
        Tuple[can_sniff: bool, error_message: str]
    """
    # Проверка прав администратора
    if not is_admin():
        return False, "Требуются права администратора для захвата пакетов. Запустите программу от имени администратора."
    
    # Проверка доступности Scapy
    try:
        from scapy.all import conf, get_if_list
        
        # Проверяем наличие интерфейсов
        interfaces = get_if_list()
        if not interfaces:
            return False, "Не найдено сетевых интерфейсов"
        
        # На Windows проверяем Npcap/WinPcap
        if sys.platform == 'win32':
            try:
                from scapy.arch.windows import get_windows_if_list
                win_interfaces = get_windows_if_list()
                if not win_interfaces:
                    return False, "Npcap/WinPcap не установлен или не найдены интерфейсы. Установите Npcap: https://npcap.com/"
            except ImportError:
                return False, "Не удалось импортировать модули Windows для Scapy"
            except Exception as e:
                return False, f"Ошибка при проверке Npcap: {str(e)}"
        
        return True, ""
    
    except ImportError as e:
        return False, f"Scapy не установлен: {str(e)}"
    except Exception as e:
        return False, f"Ошибка при проверке Scapy: {str(e)}"


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