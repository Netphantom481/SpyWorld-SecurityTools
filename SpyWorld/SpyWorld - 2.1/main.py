# ===========================
# SPYWORLD - Versión Completa Hacker
# ===========================
import tkinter as tk
from tkinter import ttk, filedialog
import requests
from bs4 import BeautifulSoup
import socket
import random
import string
import whois
import json
import platform
import subprocess
import os
from cryptography.fernet import Fernet
import json
import os

# Cargar o crear archivo de configuración
CONFIG_FILE = "config.json"

def cargar_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    else:
        return {"modo_oscuro": True}

def guardar_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

config = cargar_config()  # <-- ESTO DEFINE 'config'


# ===========================
# FUNCIONES DE RED Y HACKING
# ===========================

# Analizador Web
def obtener_info_ip(ip):
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}").json()
        return json.dumps(data, indent=4)
    except:
        return "No se pudo obtener la info."
    
def escanear_puertos(host):
    puertos_abiertos = []
    for puerto in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        resultado = sock.connect_ex((host, puerto))
        if resultado == 0:
            puertos_abiertos.append(puerto)
        sock.close()
    return puertos_abiertos

def obtener_whois(dominio):
    try:
        w = whois.whois(dominio)
        return str(w)
    except:
        return "Error al obtener WHOIS"

def detectar_dispositivos_red():
    sistema = platform.system()
    comando = "arp -a"
    resultado = subprocess.getoutput(comando)
    return resultado

def spoof_user_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Linux; Android 11)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    ]
    return random.choice(agents)

# ===========================
# FUNCIONES DE ENCRIPTACIÓN Y DESENCRIPTACIÓN
# ===========================

def generar_clave():
    return Fernet.generate_key()

def encriptar_mensaje(mensaje, clave):
    f = Fernet(clave)
    mensaje_encriptado = f.encrypt(mensaje.encode())
    return mensaje_encriptado

def desencriptar_mensaje(mensaje_encriptado, clave):
    f = Fernet(clave)
    mensaje_desencriptado = f.decrypt(mensaje_encriptado).decode()
    return mensaje_desencriptado

# Funciones de encriptación de archivos
def encriptar_archivo(archivo_original, archivo_encriptado, clave):
    f = Fernet(clave)
    with open(archivo_original, "rb") as file:
        contenido = file.read()
    contenido_encriptado = f.encrypt(contenido)
    with open(archivo_encriptado, "wb") as file:
        file.write(contenido_encriptado)
    return f"Archivo encriptado guardado como {archivo_encriptado}"

def desencriptar_archivo(archivo_encriptado, archivo_desencriptado, clave):
    f = Fernet(clave)
    with open(archivo_encriptado, "rb") as file:
        contenido_encriptado = file.read()
    contenido_desencriptado = f.decrypt(contenido_encriptado)
    with open(archivo_desencriptado, "wb") as file:
        file.write(contenido_desencriptado)
    return f"Archivo desencriptado guardado como {archivo_desencriptado}"

# ===========================
# FUNCIONES DE CARGA VISUAL
# ===========================

def mostrar_cargando(widget):
    widget.insert(tk.END, "⏳ Cargando...\n")
    widget.update_idletasks()

def ocultar_cargando(widget):
    contenido = widget.get("1.0", tk.END)
    nuevo_contenido = contenido.replace("⏳ Cargando...\n", "")
    widget.delete("1.0", tk.END)
    widget.insert(tk.END, nuevo_contenido)

# ===========================
# INTERFAZ GRÁFICA - GUI
# ===========================

ventana = tk.Tk()
ventana.title("SpyWorld Ultimate")
ventana.geometry("700x700")
ventana.configure(bg="#121212")

notebook = ttk.Notebook(ventana)
notebook.pack(padx=10, pady=10, expand=True, fill="both")

estilo = ttk.Style()
estilo.theme_use('default')
estilo.configure('.', background='#121212', foreground='#4CAF50', fieldbackground='#333')

# ===========================
# PESTAÑAS Y APARTADOS
# ===========================

# Apartado de análisis web
frame_analizador = tk.Frame(notebook, bg="#121212")
notebook.add(frame_analizador, text="🌐 Analizador Web")

entrada_url = tk.Entry(frame_analizador, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_url.pack(pady=10)

salida_analizador = tk.Text(frame_analizador, height=20, width=80, bg="#222", fg="#00aa00")
salida_analizador.pack()

# ===========================
# FUNCIONES DE SEGURIDAD ADICIONALES
# ===========================

def verificar_encabezados(r):
    encabezados_criticos = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy"]
    encabezados = r.headers
    resultado = []
    for encabezado in encabezados_criticos:
        if encabezado in encabezados:
            resultado.append(f"{encabezado}: {encabezados[encabezado]}")
        else:
            resultado.append(f"{encabezado}: No presente")
    return "\n".join(resultado)

def comprobar_sql_injection(url):
    parametros = ["' OR 1=1 --", '" OR 1=1 --', "'; DROP TABLE users --", '"><script>alert(1)</script>']
    vulnerable = False
    for param in parametros:
        prueba_url = f"{url}{param}"
        try:
            r = requests.get(prueba_url, timeout=5)
            if r.status_code == 200:
                vulnerable = True
                break
        except:
            continue
    return vulnerable

def verificar_https(url):
    if url.startswith("https://"):
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return "HTTPS habilitado y certificado SSL válido"
        except:
            return "Error al verificar HTTPS"
    else:
        return "No usa HTTPS"

# ===========================
# FUNCIONES DE ANÁLISIS MEJORADO
# ===========================

def ejecutar_analisis_mejorado(url):
    try:
        ip = socket.gethostbyname(url.split("//")[1])
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        titulo = soup.title.string if soup.title else "Sin título"

        vulnerabilidad_sql = comprobar_sql_injection(url)
        encabezados = verificar_encabezados(r)
        https_check = verificar_https(url)

        salida_analizador.delete(1.0, tk.END)
        salida_analizador.insert(tk.END, f"IP: {ip}\nTítulo: {titulo}\nCódigo: {r.status_code}\n")
        salida_analizador.insert(tk.END, f"\nEncabezados de Seguridad:\n{encabezados}\n")
        salida_analizador.insert(tk.END, f"\nHTTPS: {https_check}\n")
        salida_analizador.insert(tk.END, f"\nSQL Injection Vulnerable: {'Sí' if vulnerabilidad_sql else 'No'}\n")
        salida_analizador.insert(tk.END, f"\nUser-Agent Spoof: {spoof_user_agent()}\n")
    except Exception as e:
        salida_analizador.insert(tk.END, f"Error: {e}\n")
    ocultar_cargando(salida_analizador)

def analizar_mejorado():
    url = entrada_url.get()
    if not url.startswith("http"):
        url = "http://" + url
    salida_analizador.delete(1.0, tk.END)
    mostrar_cargando(salida_analizador)
    ventana.after(100, lambda: ejecutar_analisis_mejorado(url))

boton_analizar = tk.Button(frame_analizador, text="Analizar", command=analizar_mejorado, bg="#444", fg="#4CAF50")
boton_analizar.pack()


# Apartado de rastreo de IP
frame_ip = tk.Frame(notebook, bg="#121212")
notebook.add(frame_ip, text="📍 GeoIP")

entrada_ip = tk.Entry(frame_ip, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_ip.pack(pady=10)

salida_ip = tk.Text(frame_ip, height=15, width=80, bg="#222", fg="#00aa00")
salida_ip.pack()

def rastrear():
    ip = entrada_ip.get()
    salida_ip.delete(1.0, tk.END)
    mostrar_cargando(salida_ip)
    ventana.after(100, lambda: ejecutar_rastreo(ip))

def ejecutar_rastreo(ip):
    info = obtener_info_ip(ip)
    salida_ip.delete(1.0, tk.END)
    salida_ip.insert(tk.END, info)
    ocultar_cargando(salida_ip)

boton_rastrear = tk.Button(frame_ip, text="Rastrear IP", command=rastrear, bg="#444", fg="#4CAF50")
boton_rastrear.pack()

# Apartado WHOIS
frame_whois = tk.Frame(notebook, bg="#121212")
notebook.add(frame_whois, text="📋 WHOIS")

entrada_dominio = tk.Entry(frame_whois, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_dominio.pack(pady=10)

salida_whois = tk.Text(frame_whois, height=15, width=80, bg="#222", fg="#00aa00")
salida_whois.pack()

def buscar_whois():
    dominio = entrada_dominio.get()
    salida_whois.delete(1.0, tk.END)
    mostrar_cargando(salida_whois)
    ventana.after(100, lambda: ejecutar_whois(dominio))

def ejecutar_whois(dominio):
    data = obtener_whois(dominio)
    salida_whois.delete(1.0, tk.END)
    salida_whois.insert(tk.END, data)
    ocultar_cargando(salida_whois)

boton_whois = tk.Button(frame_whois, text="Buscar WHOIS", command=buscar_whois, bg="#444", fg="#4CAF50")
boton_whois.pack()

# Apartado de escáner de puertos
frame_puertos = tk.Frame(notebook, bg="#121212")
notebook.add(frame_puertos, text="🔍 Escáner de Puertos")

entrada_host = tk.Entry(frame_puertos, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_host.pack(pady=10)

salida_puertos = tk.Text(frame_puertos, height=10, width=80, bg="#222", fg="#00aa00")
salida_puertos.pack()

def escanear():
    host = entrada_host.get()
    salida_puertos.delete(1.0, tk.END)
    mostrar_cargando(salida_puertos)
    ventana.after(100, lambda: ejecutar_escaneo(host))

def ejecutar_escaneo(host):
    puertos = escanear_puertos(host)
    salida_puertos.delete(1.0, tk.END)
    salida_puertos.insert(tk.END, f"Puertos abiertos: {puertos}")
    ocultar_cargando(salida_puertos)

boton_escanear = tk.Button(frame_puertos, text="Escanear Puertos", command=escanear, bg="#444", fg="#4CAF50")
boton_escanear.pack()

# ===========================
# APARTADO DE GENERADOR DE CONTRASEÑAS
# ===========================

frame_pass = tk.Frame(notebook, bg="#121212")
notebook.add(frame_pass, text="🔑 Generador Password")

salida_pass = tk.Text(frame_pass, height=5, width=60, bg="#222", fg="#00aa00")
salida_pass.pack(pady=10)

def generar():
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contra = ''.join(random.choice(caracteres) for _ in range(16))
    salida_pass.delete(1.0, tk.END)
    salida_pass.insert(tk.END, contra)

boton_generar = tk.Button(frame_pass, text="Generar Contraseña", command=generar, bg="#444", fg="#4CAF50")
boton_generar.pack()

# ===========================
# APARTADO DE ENCRIPTADOR/DESENCRIPTADOR
# ===========================

frame_encriptador = tk.Frame(notebook, bg="#121212")
notebook.add(frame_encriptador, text="🔐 Encriptador/Desencriptador")

entrada_texto = tk.Entry(frame_encriptador, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_texto.pack(pady=10)

salida_encriptado = tk.Text(frame_encriptador, height=5, width=60, bg="#222", fg="#00aa00")
salida_encriptado.pack(pady=10)

clave = generar_clave()

# Encriptar mensaje
def encriptar():
    texto = entrada_texto.get()
    mensaje_encriptado = encriptar_mensaje(texto, clave)
    salida_encriptado.delete(1.0, tk.END)
    salida_encriptado.insert(tk.END, mensaje_encriptado.decode())

# Desencriptar mensaje
def desencriptar():
    texto = entrada_texto.get()
    try:
        mensaje_encriptado = texto.encode()
        mensaje_desencriptado = desencriptar_mensaje(mensaje_encriptado, clave)
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, mensaje_desencriptado)
    except Exception as e:
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, f"Error: {e}")

# Funciones para encriptar y desencriptar archivos
def seleccionar_archivo_encriptar():
    archivo = filedialog.askopenfilename(title="Seleccionar archivo para encriptar")
    if archivo:
        archivo_encriptado = archivo + ".encrypted"
        resultado = encriptar_archivo(archivo, archivo_encriptado, clave)
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, resultado)

def seleccionar_archivo_desencriptar():
    archivo = filedialog.askopenfilename(title="Seleccionar archivo para desencriptar")
    if archivo:
        archivo_desencriptado = archivo + ".decrypted"
        resultado = desencriptar_archivo(archivo, archivo_desencriptado, clave)
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, resultado)

# Botones para encriptar y desencriptar
boton_encriptar = tk.Button(frame_encriptador, text="Encriptar Mensaje", command=encriptar, bg="#444", fg="#4CAF50")
boton_encriptar.pack(pady=5)

boton_desencriptar = tk.Button(frame_encriptador, text="Desencriptar Mensaje", command=desencriptar, bg="#444", fg="#4CAF50")
boton_desencriptar.pack(pady=5)

boton_encriptar_archivo = tk.Button(frame_encriptador, text="Encriptar Archivo", command=seleccionar_archivo_encriptar, bg="#444", fg="#4CAF50")
boton_encriptar_archivo.pack(pady=5)

boton_desencriptar_archivo = tk.Button(frame_encriptador, text="Desencriptar Archivo", command=seleccionar_archivo_desencriptar, bg="#444", fg="#4CAF50")
boton_desencriptar_archivo.pack(pady=5)

# Ejecutar
ventana.mainloop()

