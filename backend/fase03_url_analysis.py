"""
url_analysis.py
----------------
Fase 3: extracción y análisis de URLs dentro del cuerpo del correo.

Recibe un CorreoParseado y devuelve una lista de AnalisisURL, una por
cada URL encontrada. La consulta a servicios externos de reputación
(VirusTotal) NO vive aquí — eso es reputation.py (Fase 3b, opcional).
"""

from dataclasses import dataclass, field
from datetime import datetime
import re
import concurrent.futures

import tldextract
import dns.resolver
import whois

from backend.fase01_email_parser import CorreoParseado

_PATRON_URL = re.compile(r"https?://[^\s\"'<>]+")
DIAS_DOMINIO_RECIENTE = 30  # umbral: dominio más nuevo que esto se marca como sospechoso


@dataclass
class AnalisisURL:
    """Resultado del análisis de una URL individual encontrada en el correo."""

    url_original: str
    dominio: str
    subdominio: str
    tld: str
    antiguedad_dias: int | None      # None si no se pudo consultar whois
    tiene_registros_mx: bool
    alertas: list[str] = field(default_factory=list)


def analizar_urls(correo: CorreoParseado) -> list[AnalisisURL]:
    """Punto de entrada del módulo."""
    urls_texto = _extraer_urls(correo.cuerpo_texto)
    urls_html = _extraer_urls(correo.cuerpo_html)
    urls_unicas = list(dict.fromkeys(urls_texto + urls_html))  # sin duplicados, conserva orden

    resultados: list[AnalisisURL] = []
    for url in urls_unicas:
        subdominio, dominio, tld = _separar_dominio(url)
        dominio_completo = f"{dominio}.{tld}" if dominio and tld else ""

        antiguedad = _consultar_antiguedad_dominio(dominio_completo) if dominio_completo else None
        tiene_mx = _verificar_registros_dns(dominio_completo) if dominio_completo else False

        alertas: list[str] = []
        if antiguedad is not None and antiguedad < DIAS_DOMINIO_RECIENTE:
            alertas.append(f"Dominio registrado hace solo {antiguedad} día(s)")
        if dominio_completo and not tiene_mx:
            alertas.append("El dominio no tiene registros MX configurados")

        resultados.append(
            AnalisisURL(
                url_original=url,
                dominio=dominio,
                subdominio=subdominio,
                tld=tld,
                antiguedad_dias=antiguedad,
                tiene_registros_mx=tiene_mx,
                alertas=alertas,
            )
        )

    return resultados


def _extraer_urls(texto: str) -> list[str]:
    """Encuentra todas las URLs http(s) dentro de un texto (plano o HTML)."""
    if not texto:
        return []
    return _PATRON_URL.findall(texto)


def _separar_dominio(url: str) -> tuple[str, str, str]:
    """
    Separa una URL en (subdominio, dominio, tld) usando tldextract.
    Ej: "https://login.paypal-secure.com/x" -> ("login", "paypal-secure", "com")
    """
    extraido = tldextract.extract(url)
    return extraido.subdomain, extraido.domain, extraido.suffix


def _consultar_antiguedad_dominio(dominio_completo: str) -> int | None:
    """
    Consulta WHOIS y devuelve la antigüedad del dominio en días.
    Usa un ThreadPoolExecutor con timeout de 5 segundos para evitar
    que la aplicación se congele si el servidor whois no responde.
    """
    def _hacer_consulta():
        info = whois.whois(dominio_completo)
        creacion = info.creation_date
        if isinstance(creacion, list):
            creacion = creacion[0]
        if creacion is None:
            return None
        return (datetime.now() - creacion).days

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            futuro = executor.submit(_hacer_consulta)
            return futuro.result(timeout=5.0)
    except Exception:
        return None


def _verificar_registros_dns(dominio_completo: str) -> bool:
    """
    Verifica si el dominio tiene registros MX válidos. Nunca lanza
    excepción — cualquier fallo de resolución se interpreta como
    'sin registros' (señal de riesgo, no error del programa).
    """
    try:
        dns.resolver.resolve(dominio_completo, "MX")
        return True
    except Exception:
        return False
