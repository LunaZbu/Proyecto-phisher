/*
 * app.js
 * ------
 * Lógica del frontend. Programación estructurada: cada función tiene
 * una sola responsabilidad y se llama explícitamente, sin clases.
 *
 * Contrato con el backend (ver backend/api.py):
 *   pywebview.api.seleccionar_archivo()        -> ruta (string) | null
 *   pywebview.api.analizar_correo(rutaOEml)    -> dict con remitente,
 *                                                  asunto, auth, urls, veredicto
 */

// ---------- Estado local (solo contadores del panel) ----------

const contadores = {
  analizados: 0,
  phishing: 0,
  legitimos: 0,
};

// ---------- Punto de entrada ----------

document.addEventListener("DOMContentLoaded", () => {
  inicializarDropzone();
  inicializarBotones();
  inicializarModalPegar();
  inicializarSpotlight();
});

// ---------- Spotlight que sigue al cursor (estilo Caelestia) ----------

function inicializarSpotlight() {
  document.querySelectorAll(".spotlight").forEach((elemento) => {
    elemento.addEventListener("mousemove", (evento) => {
      const rect = elemento.getBoundingClientRect();
      elemento.style.setProperty("--x", `${evento.clientX - rect.left}px`);
      elemento.style.setProperty("--y", `${evento.clientY - rect.top}px`);
    });
  });
}

// ---------- Dropzone (drag & drop) ----------

function inicializarDropzone() {
  const dropzone = document.getElementById("dropzone");

  dropzone.addEventListener("dragover", (evento) => {
    evento.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (evento) => {
    evento.preventDefault();
    dropzone.classList.remove("dragover");

    const archivo = evento.dataTransfer.files[0];
    if (archivo) {
      manejarArchivoLocal(archivo);
    }
  });

  // Clic en la zona (fuera de los botones) también abre el explorador,
  // salvo mientras dura el análisis.
  dropzone.addEventListener("click", (evento) => {
    if (dropzone.classList.contains("analizando")) return;
    if (evento.target.closest(".btn")) return; // los botones tienen su propio handler
    document.getElementById("input-archivo").click();
  });

  document.getElementById("input-archivo").addEventListener("change", (evento) => {
    const archivo = evento.target.files[0];
    if (archivo) {
      manejarArchivoLocal(archivo);
    }
  });
}

// ---------- Botones principales ----------

function inicializarBotones() {
  document.getElementById("btn-seleccionar").addEventListener("click", async (evento) => {
    evento.stopPropagation();
    await seleccionarArchivoDesdeBackend();
  });

  document.getElementById("btn-pegar").addEventListener("click", (evento) => {
    evento.stopPropagation();
    abrirModalPegar();
  });
}

// ---------- Modal "Pegar contenido" ----------

function inicializarModalPegar() {
  document.getElementById("btn-cancelar-pegar").addEventListener("click", cerrarModalPegar);

  document.getElementById("btn-confirmar-pegar").addEventListener("click", () => {
    const contenido = document.getElementById("textarea-pegar").value.trim();
    if (!contenido) return;
    cerrarModalPegar();
    analizarContenidoPegado(contenido);
  });
}

function abrirModalPegar() {
  document.getElementById("textarea-pegar").value = "";
  document.getElementById("modal-pegar").hidden = false;
}

function cerrarModalPegar() {
  document.getElementById("modal-pegar").hidden = true;
}

// ---------- Flujo: archivo soltado/seleccionado desde el navegador (drag&drop) ----------

function manejarArchivoLocal(archivo) {
  const lector = new FileReader();
  lector.onload = () => analizarContenidoPegado(lector.result);
  lector.readAsText(archivo);
}

// ---------- Flujo: botón "Seleccionar archivo" (diálogo nativo vía backend) ----------

async function seleccionarArchivoDesdeBackend() {
  if (!tieneBackend()) {
    mostrarInfo("Backend no disponible en este entorno (ejecuta la app con pywebview).");
    return;
  }

  const ruta = await window.pywebview.api.seleccionar_archivo();
  if (!ruta) return; // el usuario canceló el diálogo

  mostrarCargando(`Analizando: ${ruta}`);
  const resultado = await window.pywebview.api.analizar_correo(ruta);
  procesarResultado(resultado);
}

// ---------- Flujo: contenido pegado o leído en el navegador ----------

async function analizarContenidoPegado(contenido) {
  if (!tieneBackend()) {
    mostrarInfo("Backend no disponible en este entorno (ejecuta la app con pywebview).");
    return;
  }

  mostrarCargando("Analizando contenido...");
  const resultado = await window.pywebview.api.analizar_correo(contenido);
  procesarResultado(resultado);
}

function tieneBackend() {
  return typeof window.pywebview !== "undefined";
}

// ---------- Estados visuales de carga (info-bar + dropzone) ----------

function mostrarCargando(mensaje = "Analizando...") {
  const barra = document.getElementById("info-bar");
  barra.classList.remove("completado", "error");
  barra.classList.add("cargando"); // reloj girando + luz beige en el borde
  document.getElementById("dropzone").classList.add("analizando"); // puntos en ola
  mostrarInfo(mensaje);
}

function ocultarCargando(exitoso = true) {
  const barra = document.getElementById("info-bar");
  barra.classList.remove("cargando");
  barra.classList.toggle("completado", exitoso); // check verde si terminó bien
  document.getElementById("dropzone").classList.remove("analizando");
}

// ---------- Procesar y pintar el resultado ----------

function procesarResultado(resultado) {
  const barra = document.getElementById("info-bar");

  if (!resultado || resultado.error) {
    ocultarCargando(false);
    barra.classList.add("error"); // alerta carmesí en la barra de estado
    mostrarInfo(`[!] Error durante el análisis: ${resultado ? resultado.error : "desconocido"}`);
    return;
  }

  ocultarCargando(true);
  barra.classList.remove("error");
  pintarMetadatos(resultado);
  pintarVeredicto(resultado.veredicto);
  actualizarContadores(resultado.veredicto.nivel);
  mostrarInfo("Análisis completado.");
}

function pintarMetadatos(resultado) {
  document.getElementById("valor-remitente").textContent = resultado.remitente || "— sin datos —";
  document.getElementById("valor-asunto").textContent = resultado.asunto || "— sin datos —";
  document.getElementById("valor-ip").textContent = resultado.ip_origen || "—.—.—.—";

  const cantidadUrls = (resultado.urls || []).length;
  document.getElementById("valor-urls").textContent =
    cantidadUrls > 0 ? `${cantidadUrls} URL(s) detectada(s)` : "Sin URLs detectadas";
}

// ---------- Veredicto de riesgo (tarjeta, color y medidor) ----------

function pintarVeredicto(veredicto) {
  const tarjeta = document.getElementById("verdict-card");
  const icono = document.getElementById("verdict-icon");
  const texto = document.getElementById("verdict-text");
  const hint = document.getElementById("verdict-hint");

  const niveles = ["legitimo", "sospechoso", "phishing"];
  tarjeta.classList.remove(...niveles.map((nivel) => `nivel-${nivel}`));
  icono.classList.remove(...niveles);

  tarjeta.classList.add(`nivel-${veredicto.nivel}`);
  icono.classList.add(veredicto.nivel);
  reiniciarAnimacion(icono);
  reiniciarAnimacion(texto);

  const etiquetas = {
    legitimo: "Correo<br>legítimo",
    sospechoso: "Correo<br>sospechoso",
    phishing: "Phishing<br>detectado",
  };
  texto.innerHTML = etiquetas[veredicto.nivel] || "Sin<br>clasificar";

  if (typeof veredicto.puntaje === "number") {
    pintarMedidorRiesgo(veredicto.puntaje);
    hint.textContent = `Puntaje de riesgo: ${veredicto.puntaje}/100`;
  } else {
    ocultarMedidorRiesgo();
    hint.textContent = "";
  }
}

function pintarMedidorRiesgo(puntaje) {
  const medidor = document.getElementById("verdict-meter");
  const relleno = document.getElementById("verdict-meter-fill");

  const valor = Math.max(0, Math.min(100, puntaje));
  medidor.hidden = false;
  relleno.style.width = "0%";
  // Siguiente frame: así la transición del CSS anima el llenado desde 0
  requestAnimationFrame(() => {
    relleno.style.width = `${valor}%`;
  });
}

function ocultarMedidorRiesgo() {
  document.getElementById("verdict-meter").hidden = true;
  document.getElementById("verdict-meter-fill").style.width = "0%";
}

function reiniciarAnimacion(elemento) {
  elemento.classList.remove("aparecer");
  void elemento.offsetWidth; // fuerza reflow para reiniciar la animación
  elemento.classList.add("aparecer");
}

// ---------- Contadores del panel lateral ----------

function actualizarContadores(nivel) {
  contadores.analizados += 1;
  if (nivel === "phishing") contadores.phishing += 1;
  if (nivel === "legitimo") contadores.legitimos += 1;

  document.getElementById("contador-analizados").textContent = contadores.analizados;
  document.getElementById("contador-phishing").textContent = contadores.phishing;
  document.getElementById("contador-legitimos").textContent = contadores.legitimos;
}

// ---------- Barra de información/estado ----------

function mostrarInfo(mensaje) {
  document.getElementById("info-bar-texto").textContent = mensaje;
}
