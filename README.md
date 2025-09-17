# IoT_integridad
# Mini-Lab IoT: Integridad & Capas (Streamlit)

**Objetivo:** aplicación educativa en Streamlit para entender integridad de datos (SHA256 vs HMAC) y trade-offs de capas IoT (protocolo, ancho de banda, latencia, consumo).

## Estructura del repo




## Contenido
- **Sesión 1 — Integridad:** Simula sensor → canal (pérdida, latencia, tampering) y compara SHA256 vs HMAC. Visualiza puntos rojos donde la verificación falla.
- **Sesión 2 — Capas IoT:** Selector de protocolo (WiFi/LoRaWAN/Zigbee/NB-IoT), #sensores y alertas. Calcula BW requerido vs disponible, score heurístico y muestra un bar chart.
- **Caso & Entregables:** instrucciones para subir capturas y reflexiones.

## Requisitos
- Python packages (archivo `requirements.txt`):
  - streamlit
  - numpy
  - matplotlib

## Pasos para desplegar en Streamlit Cloud (sin CLI)
1. Crea un repositorio nuevo en GitHub llamado `iot-integridad-lab`.
2. Sube **por la web UI** los archivos: `app.py`, `requirements.txt`, `README.md` y opcionalmente `docs/caso.pdf`.
3. Ve a https://share.streamlit.io → "New app" → conecta con GitHub → selecciona tu repo y rama (p.ej. `main`) → Main file: `app.py` → Deploy.


##RUTA APLICACION 

https://iotaboratory.streamlit.app/

