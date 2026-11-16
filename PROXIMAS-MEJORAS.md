# Phishing-Analyzer 🎣🛡️

## 🎯 ¿Cómo funciona hoy? (Fase Actual)
Actualmente, la herramienta funciona como una **aplicación de escritorio**:
- **Análisis integral:** Revisa remitentes, valida la autenticidad del correo (SPF, DKIM, DMARC), analiza los enlaces web (URLs) y emite un nivel de riesgo (*Legítimo*, *Sospechoso* o *Phishing*).
- **Procesamiento 100% local:** Todo el análisis se ejecuta en la computadora del usuario, protegiendo la privacidad de los correos.
- **Tecnologías actuales:** Desarrollado en **Python** con una interfaz gráfica basada en **HTML, CSS, JavaScript y PyWebView**.

---

## 🚀 La Próxima Evolución: Hacia una Plataforma Web
Para hacer que la herramienta sea mucho más accesible, escalable y profesional, el proyecto se encuentra en transición hacia una **plataforma web en la nube**.

### ¿Cuál es el cambio principal?
* **Ya no será necesario descargar ni instalar nada en tu computadora.**
* Los usuarios podrán acceder directamente desde su navegador web (Chrome, Firefox, Edge, etc.) como cualquier sitio web moderno.
* Cualquier persona, desde cualquier dispositivo o sistema operativo (Windows, Linux, Mac o móvil), podrá usar la herramienta al instante.

### Nuevas Tecnologías a Implementar
1. **API Web Moderna (FastAPI):**  
   El motor de análisis en Python se convertirá en un servicio web rápido y ligero que procesará los correos a través de peticiones por internet.
2. **Base de Datos Organizada (PostgreSQL):**  
   Permitirá guardar un historial de los correos analizados para llevar estadísticas, consultar veredictos anteriores y llevar una trazabilidad organizada de amenazas.
3. **Contenedores y Portabilidad (Docker):**  
   Garantiza que la plataforma, su base de datos y sus servicios se puedan desplegar y poner en marcha fácilmente en cualquier servidor o nube sin errores de compatibilidad.

---

## 🛠️ ¿Cómo probar la versión actual en tu equipo?

1. Clona el repositorio:
   ```bash

   git clone https://github.com/LunaZbu/Proyecto-phisher.git
   cd Proyecto-phisher

   
2. **En Windows** 
  python -m venv venv
  venv\Scripts\activate


3. **Linux / macOS:**
  python -m venv venv
  source venv/bin/activate


4. **Instalar dependencias**
  pip install -r requirements.txt


5. **Ejecuta la aplicacion:**
  python3 main.py
