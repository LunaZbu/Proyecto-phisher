"""
email_parser.py
----------------
Fase 1: parseo de correos .eml.

Responsabilidad única de este módulo: convertir un .eml (desde archivo
o desde texto crudo pegado) en una estructura de datos limpia
(CorreoParseado) que el resto del backend pueda consumir.

Nada de heurísticas de phishing aquí — eso vive en auth_checks.py y
url_analysis.py. Este módulo SOLO extrae datos.
"""

from dataclasses import dataclass, field
from email.message import Message
import email
import email.policy


@dataclass
class CorreoParseado:
    """Representación limpia de un correo, lista para analizar."""

    remitente: str
    para: str
    asunto: str
    fecha: str
    headers: dict[str, str]      # headers completos, clave -> valor (para SPF/DKIM/DMARC)
    cuerpo_texto: str            # parte text/plain, si existe
    cuerpo_html: str             # parte text/html, si existe
    adjuntos: list[str] = field(default_factory=list)   # nombres de archivos adjuntos
    recibidos: list[str] = field(default_factory=list)  # todos los headers "Received" (para IP de origen)


def parsear_eml(ruta: str) -> CorreoParseado:
    """
    Parsea un archivo .eml desde disco.

    Lanza FileNotFoundError si la ruta no existe (comportamiento normal
    de open(), no lo capturamos aquí — lo maneja quien llame a esta función).
    """
    with open(ruta, "rb") as archivo:
        mensaje = email.message_from_binary_file(archivo, policy=email.policy.default)
    return _parsear_mensaje(mensaje)


def parsear_eml_desde_texto(contenido: str) -> CorreoParseado:
    """
    Parsea contenido de correo pegado directamente como texto
    (opción "Pegar contenido" de la interfaz).
    """
    mensaje = email.message_from_string(contenido, policy=email.policy.default)
    return _parsear_mensaje(mensaje)


def _parsear_mensaje(mensaje: Message) -> CorreoParseado:
    """Lógica compartida entre parsear_eml y parsear_eml_desde_texto."""
    headers = {}
    for clave, valor in mensaje.items():
        if clave in headers:
            headers[clave] += f"\\n{valor}"
        else:
            headers[clave] = str(valor)
            
    cuerpo_texto, cuerpo_html = _extraer_cuerpo(mensaje)
    adjuntos = _extraer_adjuntos(mensaje)
    recibidos = [str(valor) for valor in mensaje.get_all("Received", [])]

    return CorreoParseado(
        remitente=str(mensaje.get("From", "")),
        para=str(mensaje.get("To", "")),
        asunto=str(mensaje.get("Subject", "")),
        fecha=str(mensaje.get("Date", "")),
        headers=headers,
        cuerpo_texto=cuerpo_texto,
        cuerpo_html=cuerpo_html,
        adjuntos=adjuntos,
        recibidos=recibidos,
    )


def _extraer_cuerpo(mensaje: Message) -> tuple[str, str]:
    """
    Recorre las partes MIME del mensaje y separa el cuerpo en texto
    plano y HTML. Un correo puede traer ambos, o solo uno.
    """
    cuerpo_texto = ""
    cuerpo_html = ""

    if mensaje.is_multipart():
        for parte in mensaje.walk():
            if parte.get_content_disposition() == "attachment":
                continue

            tipo = parte.get_content_type()
            try:
                if tipo == "text/plain" and not cuerpo_texto:
                    cuerpo_texto = parte.get_content()
                elif tipo == "text/html" and not cuerpo_html:
                    cuerpo_html = parte.get_content()
            except Exception:
                # Parte con codificación inesperada — se ignora, no debe
                # romper el análisis completo del correo.
                continue
    else:
        try:
            if mensaje.get_content_type() == "text/html":
                cuerpo_html = mensaje.get_content()
            else:
                cuerpo_texto = mensaje.get_content()
        except Exception:
            pass

    return cuerpo_texto, cuerpo_html


def _extraer_adjuntos(mensaje: Message) -> list[str]:
    """Devuelve la lista de nombres de archivo de los adjuntos del correo."""
    adjuntos: list[str] = []

    if mensaje.is_multipart():
        for parte in mensaje.walk():
            if parte.get_content_disposition() == "attachment":
                nombre = parte.get_filename()
                if nombre:
                    adjuntos.append(nombre)

    return adjuntos
