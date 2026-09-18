"""
risk_engine.py
---------------
Fase 4: motor de riesgo. Combina los resultados de auth_checks.py y
url_analysis.py en un único veredicto final.

Este módulo no parsea nada ni consulta nada externo — solo recibe
resultados ya calculados y aplica las reglas de scoring. Es el único
lugar donde vive la "política" de qué tan grave es cada señal, para
poder ajustarla en un solo sitio.
"""

from dataclasses import dataclass, field

from backend.fase01_email_parser import CorreoParseado
from backend.fase02_auth_checks import ResultadoAutenticacion
from backend.fase03_url_analysis import AnalisisURL

# Umbrales de clasificación
UMBRAL_SOSPECHOSO = 30
UMBRAL_PHISHING = 60

# Pesos de cada señal (ajustables en un solo lugar)
PESO_SPF_FAIL = 20
PESO_SPF_NONE = 10
PESO_DKIM_FAIL = 20
PESO_DMARC_FAIL = 15
PESO_REMITENTE_SOSPECHOSO = 15
PESO_DOMINIO_RECIENTE = 15
PESO_SIN_REGISTROS_MX = 10

MAX_RAZONES_EN_RESUMEN = 6


@dataclass
class Veredicto:
    """Resultado final que consume la interfaz (tarjeta 'Veredicto de riesgo')."""

    puntaje: int              # 0-100, a mayor puntaje mayor riesgo
    nivel: str                # "legitimo" | "sospechoso" | "phishing"
    resumen: list[str] = field(default_factory=list)


def calcular_veredicto(
    correo: CorreoParseado,
    auth: ResultadoAutenticacion,
    urls: list[AnalisisURL],
) -> Veredicto:
    """Punto de entrada del módulo. Combina todas las señales en un score."""
    puntaje = 0
    resumen: list[str] = []

    if auth.spf_estado == "fail":
        puntaje += PESO_SPF_FAIL
    elif auth.spf_estado == "none":
        puntaje += PESO_SPF_NONE

    if auth.dkim_estado == "fail":
        puntaje += PESO_DKIM_FAIL

    if auth.dmarc_estado == "fail":
        puntaje += PESO_DMARC_FAIL

    if auth.remitente_sospechoso:
        puntaje += PESO_REMITENTE_SOSPECHOSO

    resumen.extend(auth.alertas)

    sumo_dominio_reciente = False
    sumo_sin_mx = False

    for url in urls:
        if url.antiguedad_dias is not None and url.antiguedad_dias < 30 and not sumo_dominio_reciente:
            puntaje += PESO_DOMINIO_RECIENTE
            sumo_dominio_reciente = True
        if not url.tiene_registros_mx and not sumo_sin_mx:
            puntaje += PESO_SIN_REGISTROS_MX
            sumo_sin_mx = True
        resumen.extend(url.alertas)

    resumen = list(dict.fromkeys(resumen))

    puntaje = min(puntaje, 100)
    nivel = _clasificar(puntaje)

    return Veredicto(puntaje=puntaje, nivel=nivel, resumen=resumen[:MAX_RAZONES_EN_RESUMEN])


def _clasificar(puntaje: int) -> str:
    """Traduce un puntaje numérico al nivel de riesgo (legible para la UI)."""
    if puntaje >= UMBRAL_PHISHING:
        return "phishing"
    if puntaje >= UMBRAL_SOSPECHOSO:
        return "sospechoso"
    return "legitimo"
