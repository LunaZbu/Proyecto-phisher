"""
auth_checks.py
---------------
Fase 2: verificación de autenticación del correo (SPF, DKIM, DMARC),
detección de anomalías en headers y extracción de la IP de origen.

Recibe un CorreoParseado (ya viene de email_parser.py) y trabaja
únicamente sobre correo.headers / correo.recibidos — nunca vuelve a
tocar el archivo ni el MIME crudo.
"""

from dataclasses import dataclass, field
from email.utils import parseaddr
import re

from backend.fase01_email_parser import CorreoParseado

_PATRON_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class ResultadoAutenticacion:
    """Resultado de las verificaciones de autenticación de un correo."""

    spf_estado: str          # "pass" | "fail" | "none" | "no_encontrado"
    dkim_estado: str         # "pass" | "fail" | "no_encontrado"
    dmarc_estado: str        # "pass" | "fail" | "no_encontrado"
    remitente_sospechoso: bool          # From distinto del dominio real de envío
    alertas: list[str] = field(default_factory=list)
    exitos: list[str] = field(default_factory=list)


def verificar_autenticacion(correo: CorreoParseado) -> ResultadoAutenticacion:
    """Punto de entrada del módulo."""
    auth_results = correo.headers.get("Authentication-Results", "")

    spf = _leer_spf(correo.headers, auth_results)
    dkim = _leer_dkim(auth_results)
    dmarc = _leer_dmarc(auth_results)
    sospechoso = _remitente_coincide_con_return_path(correo.headers)

    alertas: list[str] = []
    exitos: list[str] = []

    if spf == "fail":
        alertas.append("SPF: Falló la validación (remitente no autorizado)")
    elif spf == "pass":
        exitos.append("SPF: Autenticado correctamente (pass)")
    elif spf == "none":
        alertas.append("SPF: El dominio no tiene configurado registro SPF (none)")

    if dkim == "fail":
        alertas.append("DKIM: Firma digital inválida o adulterada")
    elif dkim == "pass":
        exitos.append("DKIM: Firma digital verificada con éxito (pass)")

    if dmarc == "fail":
        alertas.append("DMARC: Falló la política de seguridad DMARC")
    elif dmarc == "pass":
        exitos.append("DMARC: Cumple con la política de seguridad (pass)")

    if sospechoso:
        alertas.append("Remitente: el dominio de 'From' no coincide con 'Return-Path' (posible spoofing)")

    return ResultadoAutenticacion(
        spf_estado=spf,
        dkim_estado=dkim,
        dmarc_estado=dmarc,
        remitente_sospechoso=sospechoso,
        alertas=alertas,
        exitos=exitos,
    )


def extraer_ip_origen(recibidos: list[str]) -> str:
    """
    Heurística: busca todas las IPv4 en la cadena de headers 'Received'
    y devuelve la más cercana al origen real (se descartan IPs privadas
    cuando hay alguna pública disponible).

    No es 100% infalible (algunos proveedores ocultan la IP real), pero
    es suficiente para el alcance del proyecto.
    """
    ips_encontradas: list[str] = []
    for linea in recibidos:
        ips_encontradas.extend(_PATRON_IP.findall(linea))

    if not ips_encontradas:
        return "—.—.—.—"

    ips_publicas = [ip for ip in ips_encontradas if not _es_ip_privada(ip)]
    return ips_publicas[-1] if ips_publicas else ips_encontradas[-1]


def _es_ip_privada(ip: str) -> bool:
    """True si la IP pertenece a un rango privado/reservado (RFC 1918 + loopback)."""
    partes = ip.split(".")
    if len(partes) != 4:
        return False

    primero, segundo = int(partes[0]), int(partes[1])
    if primero == 10:
        return True
    if primero == 172 and 16 <= segundo <= 31:
        return True
    if primero == 192 and segundo == 168:
        return True
    if primero == 127:
        return True
    return False


def _leer_spf(headers: dict[str, str], authentication_results: str) -> str:
    """Busca el resultado de SPF en 'Received-SPF' o en 'Authentication-Results'."""
    received_spf = headers.get("Received-SPF", "").lower()
    if "pass" in received_spf:
        return "pass"
    if "fail" in received_spf:
        return "fail"
    if "none" in received_spf:
        return "none"

    ar = authentication_results.lower()
    if "spf=pass" in ar:
        return "pass"
    if "spf=fail" in ar:
        return "fail"
    if "spf=none" in ar:
        return "none"

    return "no_encontrado"


def _leer_dkim(authentication_results: str) -> str:
    """Extrae el resultado de DKIM desde el header Authentication-Results."""
    ar = authentication_results.lower()
    if "dkim=pass" in ar:
        return "pass"
    if "dkim=fail" in ar:
        return "fail"
    return "no_encontrado"


def _leer_dmarc(authentication_results: str) -> str:
    """Extrae el resultado de DMARC desde Authentication-Results."""
    ar = authentication_results.lower()
    if "dmarc=pass" in ar:
        return "pass"
    if "dmarc=fail" in ar:
        return "fail"
    return "no_encontrado"


def _remitente_coincide_con_return_path(headers: dict[str, str]) -> bool:
    """
    Compara el dominio de 'From' contra el dominio de 'Return-Path'.
    Devuelve True si HAY anomalía (no coinciden), False si todo bien
    o si no hay suficiente información para comparar.
    """
    from_addr = parseaddr(headers.get("From", ""))[1]
    return_path = parseaddr(headers.get("Return-Path", ""))[1]

    if not from_addr or not return_path:
        return False

    dominio_from = from_addr.split("@")[-1].lower()
    dominio_return = return_path.split("@")[-1].lower()

    return dominio_from != dominio_return
