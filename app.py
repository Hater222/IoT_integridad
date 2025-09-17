# app.py
import streamlit as st
import numpy as np
import time
import hashlib
import hmac
import os
import math
import io
import csv
import matplotlib.pyplot as plt
from collections import deque

# Page config
st.set_page_config(page_title="Mini-Lab IoT: Integridad & Capas", layout="wide")

# Reproducible randomness for teaching demos
np.random.seed(7)

st.title("Mini-Lab IoT — Integridad (HMAC) & Capas (Protocolo)")
st.markdown("Simulación educativa: sensor → canal → plataforma. Comparar SHA256 vs HMAC y explorar trade-offs de protocolos IoT.")

# ---------- Utilities: sensor, canal, hashing ----------
def sensor_temp(base=25.0, noise=0.3, drift=0.002, t=0):
    """Simula un sensor de temperatura: base + ruido gaussiano + deriva lenta."""
    return base + np.random.normal(0, noise) + drift * t

class Canal:
    def __init__(self, loss_prob=0.05, min_ms=20, max_ms=120, tamper=False, tamper_bias=10.0):
        self.loss_prob = float(loss_prob)
        self.min_ms = float(min_ms)
        self.max_ms = float(max_ms)
        self.tamper = tamper
        self.tamper_bias = float(tamper_bias)

    def enviar(self, valor):
        # pérdida
        if np.random.rand() < self.loss_prob:
            return None, None
        # latencia simulada
        lat = np.random.uniform(self.min_ms, self.max_ms)
        # manipulación en tránsito
        v = valor + self.tamper_bias if self.tamper else valor
        return v, lat

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def hmac_sha256(msg: str, key: bytes) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

# SECRET: intenta obtener de st.secrets, si no existe generar uno temporalmente
_secret_env = None
try:
    _secret_env = st.secrets.get("HMAC_SECRET", None)
except Exception:
    _secret_env = None

if _secret_env:
    SECRET = _secret_env.encode() if isinstance(_secret_env, str) else str(_secret_env).encode()
else:
    # nota: en producción poner HMAC_SECRET en Streamlit Secrets
    SECRET = os.urandom(16)

# ---------- Layout: Tabs ----------
tab1, tab2, tab3 = st.tabs(["Sesión 1 — Integridad", "Sesión 2 — Capas IoT", "Caso & Entregables"])

# ------------------ Tab 1: Integridad (streaming sim) ------------------
with tab1:
    st.header("Sesión 1 — Integridad: SHA256 vs HMAC (simulación)")
    col1, col2 = st.columns([2,1])

    with col1:
        st.markdown("**Controles de simulación**")
        dur = st.slider("Duración (s)", min_value=5, max_value=60, value=20, step=5)
        loss = st.slider("Pérdida de paquetes (probabilidad)", min_value=0.0, max_value=0.30, value=0.05, step=0.01, format="%.2f")
        tamper_on = st.selectbox("Tampering", options=["off","on"], index=0, format_func=lambda x: "ON" if x=="on" else "OFF")
        verify_mode = st.selectbox("Verificación", options=["none","sha","hmac"], index=2, format_func=lambda x: {"none":"Sin verificación","sha":"SHA256","hmac":"HMAC"}[x])
        tamper_bias = st.slider("tamper_bias (°C) — cuánto altera el atacante", min_value=5.0, max_value=20.0, value=15.0, step=0.5)
        run = st.button("Ejecutar simulación")

        st.markdown("---")
        st.markdown("**Seguridad / secretos**")
        st.write("La clave HMAC usada por la demo viene de `st.secrets` si existe (clave: `HMAC_SECRET`). En producción la clave nunca va en el cliente.")
        if _secret_env:
            st.info("HMAC_SECRET encontrado en Streamlit Secrets (usado).")
        else:
            st.warning("No hay HMAC_SECRET en Secrets — usando clave temporal (solo demo).")

    with col2:
        st.markdown("**Export / Control**")
        st.write("Puedes detener la simulación con el botón 'Detener' mientras corre.")
        if 'running' not in st.session_state:
            st.session_state.running = False
        if 'stop' not in st.session_state:
            st.session_state.stop = False

        if st.session_state.running:
            if st.button("Detener"):
                st.session_state.stop = True

    # Placeholders for dynamic content
    plot_ph = st.empty()
    stats_ph = st.empty()
    info_ph = st.empty()
    download_ph = st.empty()

    if run:
        st.session_state.running = True
        st.session_state.stop = False

        # prepare canal
        canal_ok = Canal(loss_prob=loss, tamper=False, tamper_bias=0.0)
        canal_bad = Canal(loss_prob=loss, tamper=True, tamper_bias=tamper_bias)
        canal = canal_bad if tamper_on=='on' else canal_ok

        ts = []
        rx_vals = []
        verdict = []
        latencias = []

        t0 = time.time()
        sample_idx = 0
        # streaming loop
        while time.time() - t0 < dur:
            if st.session_state.stop:
                break
            t_rel = time.time() - t0
            raw = sensor_temp(t=t_rel)
            msg = f"{raw:.2f}"
            sig = None
            if verify_mode == 'sha':
                sig = sha256_str(msg)
            elif verify_mode == 'hmac':
                sig = hmac_sha256(msg, SECRET)

            # enviar por canal (posible pérdida / manipulación)
            rx, lat = canal.enviar(float(msg))
            if rx is None:
                # paquete perdido: saltar muestra
                time.sleep(0.05)
                sample_idx += 1
                continue

            ok = True
            if verify_mode == 'sha':
                ok = (sha256_str(f"{rx:.2f}") == sig)
            elif verify_mode == 'hmac':
                ok = (hmac_sha256(f"{rx:.2f}", SECRET) == sig)

            ts.append(t_rel)
            rx_vals.append(rx)
            verdict.append(ok)
            latencias.append(lat)

            # plot
            fig, ax = plt.subplots(figsize=(8,3.5))
            ax.plot(ts, rx_vals, marker='o', linewidth=1, label='Temperatura recibida (°C)')
            # highlight bad points
            bad_x = [tt for tt,v in zip(ts, verdict) if not v]
            bad_y = [vv for vv,v in zip(rx_vals, verdict) if not v]
            if bad_x:
                ax.scatter(bad_x, bad_y, s=60, edgecolor='k', c='r', label='Fallo integridad')
                ax.legend()
            ax.set_xlabel("Tiempo (s)")
            ax.set_ylabel("°C")
            ax.set_title("Temperatura recibida (stream simulado)")
            ax.grid(True)
            plot_ph.pyplot(fig)
            plt.close(fig)

            # stats
            total = len(verdict)
            malos = sum(1 for v in verdict if not v)
            stats_ph.markdown(f"**Samples:** {total}  |  **Fallos integridad:** {malos}  |  **Tampering:** {tamper_on}  |  **Verificación:** {verify_mode}")
            info_ph.markdown("""
**Qué observar:**  
- Si `SHA256` está activo, un atacante que pueda recalcular el hash puede camuflar la manipulación (hash simple es vulnerable).  
- Con `HMAC` (clave secreta) el atacante SIN la clave no puede recomputar la firma, por eso las muestras manipuladas fallan la verificación (puntos rojos).  
- En producción la clave HMAC debe guardarse en _secrets_ y el firmado hacerse en el dispositivo o en un módulo seguro.
""")

            sample_idx += 1
            time.sleep(0.25)

        st.session_state.running = False

        # download CSV
        if rx_vals:
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(["t_rel","rx_val","verificado","lat_ms"])
            for t_rel,rx_v,ok,lat in zip(ts, rx_vals, verdict, latencias):
                writer.writerow([f"{t_rel:.3f}", f"{rx_v:.2f}", str(ok), f"{lat:.1f}" if lat is not None else ""])
            csv_data = csv_buffer.getvalue()
            download_ph.download_button(label="Exportar muestras (CSV)", data=csv_data, file_name="sesion1_muestras.csv", mime="text/csv")

# ------------------ Tab 2: Capas IoT ------------------
with tab2:
    st.header("Sesión 2 — Capas IoT: Protocolo, BW, Latencia y Score")
    colp, coll = st.columns([2,1])

    with colp:
        proto = st.selectbox("Protocolo", options=["WiFi","LoRaWAN","Zigbee","NB-IoT"], index=1)
        n_sens = st.slider("# Sensores", min_value=1, max_value=20, value=4)
        alertas = st.checkbox("Alertas habilitadas", value=True)
        st.markdown("Valores didácticos aproximados (no normativos).")

    # perfil de protocolos (didáctico)
    def perfil_protocolo(p):
        if p=="WiFi":   return dict(bw=54000, lat=30,  mAh=200)
        if p=="Zigbee": return dict(bw=250,   lat=60,  mAh=30)
        if p=="LoRaWAN":return dict(bw=5,     lat=500, mAh=5)
        if p=="NB-IoT": return dict(bw=60,    lat=300, mAh=10)

    perf = perfil_protocolo(proto)
    bw_need = n_sens * 2  # kbps per sensor approx
    ok_bw = perf["bw"] >= bw_need

    # heurístico de score
    def score_sistema(bw_ok, lat_ms, alerts, energia_mAh_dia):
        score = 0
        score += 2 if bw_ok else -2
        score += 2 if lat_ms < 200 else 0
        score += 2 if alerts else 0
        score -= 1 if energia_mAh_dia > 50 else 0
        return score

    score = score_sistema(ok_bw, perf["lat"], alertas, perf["mAh"])

    st.markdown(f"**Protocolo:** {proto}  |  **BW disponible:** {perf['bw']} kbps  |  **Latencia:** {perf['lat']} ms  |  **Consumo aprox.:** {perf['mAh']} mAh/día")
    st.markdown(f"**Sensores:** {n_sens} → BW requerido ~ {bw_need} kbps  |  **OK_BW:** {ok_bw}  |  **Score heurístico:** {score}")

    # Bar chart
    fig2, ax2 = plt.subplots(figsize=(6,3.5))
    labels = ["BW requerido","BW disponible"]
    vals = [bw_need, perf['bw']]
    ax2.bar(labels, vals)
    ax2.set_ylabel("kbps")
    ax2.set_title("Ancho de banda: requerido vs disponible")
    st.pyplot(fig2)
    plt.close(fig2)

    st.markdown("**Interpretación breve:**")
    st.write("- Si `OK_BW` es False, el protocolo no soporta el volumen de sensores sin perder datos o aumentar latencia.")
    st.write("- Protocolos como LoRaWAN tienen bajo consumo pero alta latencia: adecuados para telemetría no crítica. WiFi tiene alto BW y baja latencia pero mayor consumo.")
    st.write("- Para usar Blockchain de forma frecuente se necesita red con BW y latencia suficientes; si no, registrar solo eventos críticos (off-chain/on-chain híbrido).")

# ------------------ Tab 3: Caso & Entregables ------------------
with tab3:
    st.header("Caso & Entregables")
    st.markdown("**Entregables que deben subir** (para la práctica):")
    st.markdown("**Sesión 1**")
    st.write("1. Ejecutar: `Tampering ON` + `Verificación = HMAC`. 2. Captura del gráfico (puntos rojos visibles). 3. Subir nº de fallos e **3 líneas** de reflexión sobre por qué HMAC detecta manipulación y por qué SHA no es suficiente si el atacante puede recalcular hashes.")
    st.markdown("**Sesión 2**")
    st.write("1. Elegir un protocolo (p.ej. LoRaWAN o Zigbee). 2. Captura del `bar chart` BW requerido vs disponible. 3. **3 líneas** justificando la elección en términos latencia/consumo/BW y si sería compatible con un ledger distribuido (blockchain).")

    st.markdown("---")
    st.markdown("**Caso (placeholder)**")
    try:
        # try to link a PDF in docs if exists in deployed repo structure
        st.markdown("Si tienes `docs/caso.pdf` en el repo, estará disponible aquí en deploy.")
        st.write("Si falta el PDF, pega el texto del caso en el README o en este panel.")
    except Exception:
        st.info("No se encontró docs/caso.pdf en el repo.")

    st.markdown("---")
    st.markdown("**Notas docentes / recordatorio**")
    st.write("- El hash simple (SHA256) no protege si el atacante puede recalcular el hash tras manipular el dato; HMAC usa una clave secreta compartida y evita eso si la clave no se filtra.")
    st.write("- En producción el firmado debe realizarse en el dispositivo o en un módulo seguro y la clave guardarse en secretos (no en el cliente).")
    st.write("- Blockchain aporta trazabilidad inmutable, pero no corrige datos falsos si la entrada no está firmada correctamente en origen.")
    st.markdown("---")
    st.markdown("**Opciones extra**")
    st.write("- Botón `Exportar muestras (CSV)` aparece al finalizar una ejecución en la Sesión 1 si hay muestras.")
    st.write("- Selector `tamper_bias` permite experimentar con la magnitud de la manipulación.")
