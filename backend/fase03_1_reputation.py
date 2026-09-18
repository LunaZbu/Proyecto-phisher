"""
reputation.py
--------------
Fase 3b (OPCIONAL): consulta de reputación de URLs contra VirusTotal.

Regla de este módulo: NUNCA lanza una excepción que detenga el
análisis. Si algo falla (sin API key, sin internet, límite de cuota,
respuesta inesperada), se devuelve None y el resto del pipeline
sigue funcionando solo con las señales locales.

Para activarlo: configura la variable de entorno VIRUSTOTAL_API_KEY
con tu API key gratuita de https://www.virustotal.com/
"""

from dataclasses import dataclass
import base64
import os

import requests

TIMEOUT_SEGUNDOS = 5


@dataclass
class ResultadoReputacion:
    """Resultado de consultar una URL en VirusTotal."""

    url: str
    malicioso: bool
    motores_detectaron: int
    total_motores: int


def consultar_reputacion(url: str) -> ResultadoReputacion | None:
    """Punto de entrada del módulo. Ver docstring del módulo para el comportamiento en caso de fallo."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        respuesta = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=TIMEOUT_SEGUNDOS,
        )
        if respuesta.status_code != 200:
            return None

        datos = respuesta.json()
        stats = datos["data"]["attributes"]["last_analysis_stats"]
        maliciosos = stats.get("malicious", 0)
        total = sum(stats.values())

        return ResultadoReputacion(
            url=url,
            malicioso=maliciosos > 0,
            motores_detectaron=maliciosos,
            total_motores=total,
        )
    except Exception:
        return None
