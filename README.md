# Phishing-Analyzer 🎣🐍

## Descripción del Proyecto
Phishing-Analyzer es una herramienta de escritorio desarrollada con fines académicos que permite analizar correos electrónicos (en formato `.eml`) para determinar si presentan características de *phishing* o suplantación de identidad. 

Este proyecto fue diseñado y construido por estudiantes de sistemas como una aproximación práctica a los conceptos de ciberseguridad, enfocándose en el análisis de amenazas y la protección de la información.

## Objetivo
El propósito principal de esta aplicación es ofrecer un entorno seguro y local para evaluar correos electrónicos sospechosos. A través del análisis de las diferentes partes que componen un correo, la herramienta emite un veredicto de riesgo (Legítimo, Sospechoso o Phishing), facilitando la comprensión de los elementos que pueden hacer que un mensaje sea peligroso.

## Funcionalidades Principales
- **Análisis de Origen y Autenticidad:** Examina los registros de los servidores de correo para validar la identidad del remitente utilizando protocolos de seguridad estándar.
- **Evaluación de Enlaces (URLs):** Identifica y analiza los enlaces dentro del mensaje, revisando la procedencia y el estado de los dominios para alertar sobre sitios web engañosos.
- **Procesamiento Seguro y Local:** El análisis base se realiza directamente en el equipo del usuario, asegurando que la información contenida en los correos no se comparta innecesariamente.
- **Interfaz Amigable:** Cuenta con un panel de control intuitivo que permite cargar correos fácilmente y presenta los resultados de manera clara, detallando los motivos del veredicto.

## Tecnologías Utilizadas
El proyecto integra diversas herramientas que permiten un funcionamiento eficiente y una interfaz moderna:
- **Lógica de Análisis:** Desarrollada en **Python**, elegido por su versatilidad y eficiencia en el procesamiento de datos y la extracción de información.
- **Interfaz Visual:** Construida utilizando **HTML, CSS y JavaScript**, logrando un diseño limpio y accesible sin necesidad de frameworks complejos.
- **Integración de Escritorio:** Se empleó **PyWebView** para conectar la interfaz gráfica con el motor de análisis en Python, resultando en una aplicación nativa, ligera y fácil de ejecutar.

## Instalación y Ejecución
Para poner en marcha el proyecto en un entorno de desarrollo:

1. Asegúrate de tener Python instalado en tu equipo.
2. Clona o descarga este repositorio.
3. Se recomienda crear un entorno virtual para aislar las dependencias:
   ```bash
   python -m venv venv
   ```
4. Activa el entorno virtual e instala los requerimientos:
   ```bash
   pip install -r requirements.txt
   ```
5. Inicia la aplicación ejecutando el archivo principal:
   ```bash
   python main.py
   ```

---
*Proyecto educativo enfocado en la detección forense y seguridad informática.*
