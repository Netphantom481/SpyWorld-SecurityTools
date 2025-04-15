# ===========================
# SPYWORLD - Versión Completa Hacker
# ===========================
import tkinter as tk
from tkinter import ttk
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

# ===========================
# Funciones de red y hacking
# ===========================

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
    if sistema == "Windows":
        comando = "arp -a"
    else:
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
# Funciones de encriptación y desencriptación
# ===========================

# Generar una clave de encriptación (esto debe hacerse una sola vez)
def generar_clave():
    return Fernet.generate_key()

# Encriptar el mensaje
def encriptar_mensaje(mensaje, clave):
    f = Fernet(clave)
    mensaje_encriptado = f.encrypt(mensaje.encode())
    return mensaje_encriptado

# Desencriptar el mensaje
def desencriptar_mensaje(mensaje_encriptado, clave):
    f = Fernet(clave)
    mensaje_desencriptado = f.decrypt(mensaje_encriptado).decode()
    return mensaje_desencriptado

# ===========================
# GUI
# ===========================

ventana = tk.Tk()
ventana.title("SpyWorld Ultimate")
ventana.geometry("700x700")
ventana.configure(bg="#121212")  # Fondo más oscuro

notebook = ttk.Notebook(ventana)
notebook.pack(padx=10, pady=10, expand=True, fill="both")

estilo = ttk.Style()
estilo.theme_use('default')
estilo.configure('.', background='#121212', foreground='#4CAF50', fieldbackground='#333')  # Verde oscuro

# Analizador Web
frame_analizador = tk.Frame(notebook, bg="#121212")
notebook.add(frame_analizador, text="🌐 Analizador Web")

entrada_url = tk.Entry(frame_analizador, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_url.pack(pady=10)

salida_analizador = tk.Text(frame_analizador, height=20, width=80, bg="#222", fg="lime")
salida_analizador.pack()


def analizar():
    url = entrada_url.get()
    if not url.startswith("http"):
        url = "http://" + url

    try:
        ip = socket.gethostbyname(url.split("//")[1])
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        titulo = soup.title.string if soup.title else "Sin título"
        salida_analizador.delete(1.0, tk.END)
        salida_analizador.insert(tk.END, f"IP: {ip}\nTítulo: {titulo}\nCódigo: {r.status_code}\n")
        salida_analizador.insert(tk.END, f"\nUser-Agent Spoof: {spoof_user_agent()}\n")
    except Exception as e:
        salida_analizador.insert(tk.END, f"Error: {e}\n")

boton_analizar = tk.Button(frame_analizador, text="Analizar", command=analizar, bg="#444", fg="#4CAF50")
boton_analizar.pack()

# Contraseñas
frame_pass = tk.Frame(notebook, bg="#121212")
notebook.add(frame_pass, text="🔑 Generador Password")

salida_pass = tk.Text(frame_pass, height=5, width=60, bg="#222", fg="lime")
salida_pass.pack(pady=10)

def generar():
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contra = ''.join(random.choice(caracteres) for _ in range(16))
    salida_pass.delete(1.0, tk.END)
    salida_pass.insert(tk.END, contra)

boton_generar = tk.Button(frame_pass, text="Generar Contraseña", command=generar, bg="#444", fg="#4CAF50")
boton_generar.pack()

# IP Tracker
frame_ip = tk.Frame(notebook, bg="#121212")
notebook.add(frame_ip, text="📍 GeoIP")

entrada_ip = tk.Entry(frame_ip, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_ip.pack(pady=10)

salida_ip = tk.Text(frame_ip, height=15, width=80, bg="#222", fg="lime")
salida_ip.pack()

def rastrear():
    ip = entrada_ip.get()
    info = obtener_info_ip(ip)
    salida_ip.delete(1.0, tk.END)
    salida_ip.insert(tk.END, info)

boton_rastrear = tk.Button(frame_ip, text="Rastrear IP", command=rastrear, bg="#444", fg="#4CAF50")
boton_rastrear.pack()

# Whois
frame_whois = tk.Frame(notebook, bg="#121212")
notebook.add(frame_whois, text="📋 WHOIS")

entrada_dominio = tk.Entry(frame_whois, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_dominio.pack(pady=10)

salida_whois = tk.Text(frame_whois, height=15, width=80, bg="#222", fg="lime")
salida_whois.pack()

def buscar_whois():
    dominio = entrada_dominio.get()
    data = obtener_whois(dominio)
    salida_whois.delete(1.0, tk.END)
    salida_whois.insert(tk.END, data)

boton_whois = tk.Button(frame_whois, text="Buscar WHOIS", command=buscar_whois, bg="#444", fg="#4CAF50")
boton_whois.pack()

# Escaneo de puertos
frame_puertos = tk.Frame(notebook, bg="#121212")
notebook.add(frame_puertos, text="🔍 Escáner de Puertos")

entrada_host = tk.Entry(frame_puertos, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_host.pack(pady=10)

salida_puertos = tk.Text(frame_puertos, height=10, width=80, bg="#222", fg="lime")
salida_puertos.pack()

def escanear():
    host = entrada_host.get()
    puertos = escanear_puertos(host)
    salida_puertos.delete(1.0, tk.END)
    salida_puertos.insert(tk.END, f"Puertos abiertos en {host}:\n{puertos}")

boton_escanear = tk.Button(frame_puertos, text="Escanear Puertos", command=escanear, bg="#444", fg="#4CAF50")
boton_escanear.pack()

# Dispositivos red local
frame_red = tk.Frame(notebook, bg="#121212")
notebook.add(frame_red, text="📶 Dispositivos en Red")

salida_red = tk.Text(frame_red, height=20, width=80, bg="#222", fg="lime")
salida_red.pack()

def buscar_dispositivos():
    salida_red.delete(1.0, tk.END)
    salida_red.insert(tk.END, detectar_dispositivos_red())

boton_red = tk.Button(frame_red, text="Detectar Dispositivos", command=buscar_dispositivos, bg="#444", fg="#4CAF50")
boton_red.pack()

# Encriptador/Desencriptador
frame_encriptador = tk.Frame(notebook, bg="#121212")
notebook.add(frame_encriptador, text="🔐 Encriptador/Desencriptador")

entrada_texto = tk.Entry(frame_encriptador, width=50, fg="#4CAF50", bg="#333", insertbackground="#4CAF50")
entrada_texto.pack(pady=10)

salida_encriptado = tk.Text(frame_encriptador, height=5, width=60, bg="#222", fg="lime")
salida_encriptado.pack(pady=10)

clave = generar_clave()  # Guardar la clave para usarla en encriptación y desencriptación

def encriptar():
    texto = entrada_texto.get()
    mensaje_encriptado = encriptar_mensaje(texto, clave)
    salida_encriptado.delete(1.0, tk.END)
    salida_encriptado.insert(tk.END, mensaje_encriptado.decode())

def desencriptar():
    texto = entrada_texto.get()
    try:
        mensaje_encriptado = texto.encode()  # Aseguramos que el texto esté en bytes
        mensaje_desencriptado = desencriptar_mensaje(mensaje_encriptado, clave)
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, mensaje_desencriptado)
    except Exception as e:
        salida_encriptado.delete(1.0, tk.END)
        salida_encriptado.insert(tk.END, f"Error: {e}")

boton_encriptar = tk.Button(frame_encriptador, text="Encriptar", command=encriptar, bg="#444", fg="#4CAF50")
boton_encriptar.pack(pady=5)

boton_desencriptar = tk.Button(frame_encriptador, text="Desencriptar", command=desencriptar, bg="#444", fg="#4CAF50")
boton_desencriptar.pack(pady=5)

# Ejecutar
ventana.mainloop()
