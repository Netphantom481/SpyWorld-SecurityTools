import tkinter as tk
from tkinter import PhotoImage, ttk
import requests
from bs4 import BeautifulSoup
import socket
import random
import string

# ===========================
# Funciones de cambio de pantalla
# ===========================

def mostrar_menu():
    ocultar_todo()
    frame_menu.pack()

def mostrar_analizador():
    ocultar_todo()
    frame_analizador.pack()

def mostrar_generador():
    ocultar_todo()
    frame_generador.pack()

def mostrar_encriptador():
    ocultar_todo()
    frame_encriptador.pack()

def ocultar_todo():
    frame_menu.pack_forget()
    frame_analizador.pack_forget()
    frame_generador.pack_forget()
    frame_encriptador.pack_forget()

# ===========================
# Función analizador web
# ===========================

def analizar_web():
    url = entrada.get()
    if not url.startswith("http"):
        url = "http://" + url

    try:
        ip = socket.gethostbyname(url.split("//")[1])
        respuesta = requests.get(url, timeout=5)
        codigo = respuesta.status_code
        soup = BeautifulSoup(respuesta.text, "html.parser")
        titulo = soup.title.string if soup.title else "Sin título"

        # Comprobaciones de vulnerabilidad
        vulnerabilidades = []
        if 'X-Content-Type-Options' not in respuesta.headers:
            vulnerabilidades.append("⚠️ Falta encabezado de seguridad: X-Content-Type-Options")
        if 'Strict-Transport-Security' not in respuesta.headers:
            vulnerabilidades.append("⚠️ Falta encabezado de seguridad: Strict-Transport-Security")
        if "http://" in url and respuesta.status_code == 200:
            vulnerabilidades.append("⚠️ El sitio no redirige a HTTPS (Redirección insegura)")

        # Mostrar resultados
        salida.config(state="normal")
        salida.delete(1.0, tk.END)
        salida.insert(tk.END, f"✅ Sitio activo: {url}\n")
        salida.insert(tk.END, f"🌐 Dirección IP: {ip}\n")
        salida.insert(tk.END, f"📄 Código de respuesta: {codigo}\n")
        salida.insert(tk.END, f"🧠 Título de la página: {titulo}\n")

        # Mostrar vulnerabilidades encontradas
        if vulnerabilidades:
            salida.insert(tk.END, "\n⚠️ Vulnerabilidades detectadas:\n")
            for vuln in vulnerabilidades:
                salida.insert(tk.END, f"{vuln}\n")
        else:
            salida.insert(tk.END, "\n✅ No se detectaron vulnerabilidades.\n")

        salida.config(state="disabled")
    except Exception as e:
        salida.config(state="normal")
        salida.delete(1.0, tk.END)
        salida.insert(tk.END, f"❌ Error al analizar la web:\n{e}")
        salida.config(state="disabled")

# ===========================
# Generador de contraseñas
# ===========================

def generar_contraseña():
    longitud = 16  # Puedes cambiarlo o hacer que el usuario lo elija
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contraseña = ''.join(random.choice(caracteres) for _ in range(longitud))
    
    salida_generador.config(state="normal")
    salida_generador.delete(1.0, tk.END)
    salida_generador.insert(tk.END, f"🔐 Contraseña generada:\n{contraseña}")
    salida_generador.config(state="disabled")

# ===========================
# Encriptador de mensajes
# ===========================

def encriptar_mensaje():
    mensaje = entrada_mensaje.get()
    mensaje_encriptado = ''.join(chr(ord(c) + 5) for c in mensaje)  # Encriptación simple
    salida_encriptador.config(state="normal")
    salida_encriptador.delete(1.0, tk.END)
    salida_encriptador.insert(tk.END, f"🔒 Mensaje encriptado:\n{mensaje_encriptado}")
    salida_encriptador.config(state="disabled")

def desencriptar_mensaje():
    mensaje = entrada_mensaje.get()
    mensaje_desencriptado = ''.join(chr(ord(c) - 5) for c in mensaje)  # Desencriptación simple
    salida_encriptador.config(state="normal")
    salida_encriptador.delete(1.0, tk.END)
    salida_encriptador.insert(tk.END, f"🔓 Mensaje desencriptado:\n{mensaje_desencriptado}")
    salida_encriptador.config(state="disabled")

# ===========================
# INTERFAZ
# ===========================

ventana = tk.Tk()
ventana.title("SpyWorld")
ventana.geometry("650x450")
ventana.configure(bg="#2d2d2d")  # Fondo oscuro para la ventana

# ===========================
# MENÚ PRINCIPAL
# ===========================

frame_menu = tk.Frame(ventana, bg="#1e1e1e")

titulo_menu = tk.Label(frame_menu, text="SpyWorld HUB", fg="lime", bg="#1e1e1e", font=("Helvetica Neue", 20, 'bold'))
titulo_menu.pack(pady=20)

boton_analizador = tk.Button(frame_menu, text="🌐 Analizador Web", command=mostrar_analizador, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_analizador.pack(pady=10)

boton_generador = tk.Button(frame_menu, text="🔑 Generador de Contraseñas", command=mostrar_generador, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_generador.pack(pady=10)

boton_encriptador = tk.Button(frame_menu, text="🔒 Encriptador de Mensajes", command=mostrar_encriptador, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_encriptador.pack(pady=10)

frame_menu.pack()

# ===========================
# PANTALLA ANALIZADOR WEB
# ===========================

frame_analizador = tk.Frame(ventana, bg="#1e1e1e")

titulo_label = tk.Label(frame_analizador, text="ANALIZADOR WEB", fg="lime", bg="#1e1e1e", font=("Helvetica Neue", 18, 'bold'))
titulo_label.pack(pady=10)

entrada = tk.Entry(frame_analizador, width=50, font=("Arial", 12), bg="#333", fg="lime", insertbackground="lime")
entrada.insert(0, "ejemplo.com")
entrada.pack(pady=5)

boton = tk.Button(frame_analizador, text="Analizar", command=analizar_web, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton.pack(pady=10)

salida = tk.Text(frame_analizador, height=10, width=70, font=("Courier", 10), bg="#333", fg="lime")
salida.pack()
salida.config(state="disabled")

boton_volver = tk.Button(frame_analizador, text="⬅️ Volver al menú", command=mostrar_menu, bg="#555", fg="white", font=("Arial", 10, 'bold'), relief="solid", bd=2)
boton_volver.pack(pady=10)

# ===========================
# PANTALLA GENERADOR DE CONTRASEÑAS
# ===========================

frame_generador = tk.Frame(ventana, bg="#1e1e1e")

titulo_generador = tk.Label(frame_generador, text="Generador de Contraseñas", fg="lime", bg="#1e1e1e", font=("Helvetica Neue", 18, 'bold'))
titulo_generador.pack(pady=10)

boton_generar = tk.Button(frame_generador, text="Generar Contraseña", command=generar_contraseña, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_generar.pack(pady=10)

salida_generador = tk.Text(frame_generador, height=5, width=70, font=("Courier", 10), bg="#333", fg="lime")
salida_generador.pack()
salida_generador.config(state="disabled")

boton_volver_generador = tk.Button(frame_generador, text="⬅️ Volver al menú", command=mostrar_menu, bg="#555", fg="white", font=("Arial", 10, 'bold'), relief="solid", bd=2)
boton_volver_generador.pack(pady=10)

# ===========================
# PANTALLA ENCRIPTADOR
# ===========================

frame_encriptador = tk.Frame(ventana, bg="#1e1e1e")

titulo_encriptador = tk.Label(frame_encriptador, text="Encriptador de Mensajes", fg="lime", bg="#1e1e1e", font=("Helvetica Neue", 18, 'bold'))
titulo_encriptador.pack(pady=10)

entrada_mensaje = tk.Entry(frame_encriptador, width=50, font=("Arial", 12), bg="#333", fg="lime", insertbackground="lime")
entrada_mensaje.insert(0, "Escribe tu mensaje aquí...")
entrada_mensaje.pack(pady=5)

boton_encriptar = tk.Button(frame_encriptador, text="Encriptar", command=encriptar_mensaje, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_encriptar.pack(pady=10)

boton_desencriptar = tk.Button(frame_encriptador, text="Desencriptar", command=desencriptar_mensaje, bg="#444", fg="white", font=("Arial", 12, 'bold'), relief="solid", bd=2)
boton_desencriptar.pack(pady=10)

salida_encriptador = tk.Text(frame_encriptador, height=5, width=70, font=("Courier", 10), bg="#333", fg="lime")
salida_encriptador.pack()
salida_encriptador.config(state="disabled")

boton_volver_encriptador = tk.Button(frame_encriptador, text="⬅️ Volver al menú", command=mostrar_menu, bg="#555", fg="white", font=("Arial", 10, 'bold'), relief="solid", bd=2)
boton_volver_encriptador.pack(pady=10)

# ===========================
# EJECUTAR APP
# ===========================

ventana.mainloop()
