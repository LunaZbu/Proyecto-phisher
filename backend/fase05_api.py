"""
api.py
------
Fase 5: puente entre el frontend (JS) y el backend (Python).

Única clase de todo el proyecto (pywebview lo exige para js_api).
No contiene lógica propia — orquesta las llamadas a los módulos
estructurados y convierte los dataclasses a dict (JSON-serializable)
para que el JS los pueda leer.
"""

from dataclasses import asdict
import os

import webview

from backend import fase01_email_parser, fase02_auth_checks, fase03_url_analysis, fase04_risk_engine


class Api:

    def analizar_correo(self, ruta_o_contenido: str) -> dict:

        try:
            if len(ruta_o_contenido) < 2048 and os.path.isfile(ruta_o_contenido):
                correo = fase01_email_parser.parsear_eml(ruta_o_contenido)
            else:
                correo = fase01_email_parser.parsear_eml_desde_texto(ruta_o_contenido)

            auth = fase02_auth_checks.verificar_autenticacion(correo)
            urls = fase03_url_analysis.analizar_urls(correo)
            veredicto = fase04_risk_engine.calcular_veredicto(correo, auth, urls)
            ip_origen = fase02_auth_checks.extraer_ip_origen(correo.recibidos)

            return {
                "remitente": correo.remitente,
                "asunto": correo.asunto,
                "ip_origen": ip_origen,
                "auth": asdict(auth),
                "urls": [asdict(u) for u in urls],
                "veredicto": asdict(veredicto),
            }
        except Exception as e:
            return {"error": str(e)}

    def seleccionar_archivo(self) -> str | None:
        """
        Abre el diálogo nativo del sistema para elegir un archivo .eml
        (botón "Seleccionar archivo" del mockup).
        """
        resultado = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=(
                "Archivos de correo (*.eml;*.msg;*.txt)",
                "Todos los archivos (*.*)",
            ),
        )
        if resultado:
            return resultado[0]
        return None
