"""
main.py
-------
Punto de entrada de la aplicación. Crea la ventana pywebview, carga
el frontend y conecta la clase Api como puente.
"""

from pathlib import Path
import webview

from backend.fase05_api import Api


def main() -> None:
    ruta_frontend = Path(__file__).resolve().parent / "frontend" / "index.html"
    api = Api()
    webview.create_window(
        "Phishing-Analyzer",
        str(ruta_frontend),
        js_api=api,
        width=1200,
        height=700,
        min_size=(900, 500),
    )
    webview.start()


if __name__ == "__main__":
    main()
