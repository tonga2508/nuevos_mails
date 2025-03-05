#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para recuperar el último archivo CSV desde un servidor remoto,
procesar las cuentas de mail usando una API y enviar un correo de
confirmación con las cuentas creadas.

Formato esperado del CSV (separado por punto y coma):
    surname;name;email;password;[campo5];[campo6];[campo7]
Se utilizan solo los 4 primeros campos (los demás se ignoran).

El script se conecta vía SSH (utilizando sshpass) para recuperar el CSV.
Luego, procesa cada línea para crear la cuenta mediante la API.
Finalmente, envía un correo de confirmación con la lista de cuentas creadas.

Requisitos:
    - Python 3 (recomendado >= 3.5)
    - Módulo requests (se instala vía pip)
    - sshpass instalado en el sistema para la conexión remota

Configuración de crontab:
    Para ejecutar el script todos los días a las 23:30hs, se puede agregar
    la siguiente línea al crontab (usando "crontab -e"):
    
        30 23 * * * /usr/bin/python3 /home/nuevosmails/nuevos_mails.py

Asegúrate de que el script tenga permisos de ejecución y que las rutas
configuradas (CSV_DIR, LOG_FILE, etc.) existan o puedan ser creadas.
"""

import os
import glob
import csv
import logging
import re
import time
import requests
import secrets
import string
import smtplib
import subprocess
from email.message import EmailMessage
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# ---------------------------
# Configuración de Constantes
# ---------------------------
CSV_DIR = '/home/nuevosmails/20.4.4.4'          # Directorio local donde se guardará el CSV
REMOTE_CSV_DIR = '/home/nuevosmails/20.4.4.4'     # Directorio remoto de donde se extrae el CSV
AUTHORIZATION = "Zikdko99e0wjfh"                  # Parámetro de autorización para la API
PLANIMAIL = "cpacf"                               # Parámetro Planimail para la API
API_URL = 'https://planimail-app.planisys.net:8443/api/v1/mailbox'
LOG_FILE = '/home/nuevosmails/procesar_ultimo_csv.log'
DEFAULT_QUOTAMB = 10240                           # Valor por defecto para la cuota, si no se especifica

# Configuración de Email (SMTP)
SMTP_SERVER = 'smtpauth.cpacf.org.ar'
SMTP_PORT = 587
SMTP_USER = 'gastonld@cpacf.org.ar'
SMTP_PASS = 'cicsparg'
MAIL_FROM = SMTP_USER
# Lista de destinatarios de la confirmación
MAIL_TO = ["sysadmin@cpacf.org.ar", "otro@ejemplo.com", "tercero@ejemplo.com"]

# Datos de conexión remota (para ssh y scp)
REMOTE_IP = "201.216.236.220"
REMOTE_PORT = 22022
REMOTE_USER = "root"
REMOTE_PASS = "cpacf3951"

# ---------------------------
# Configuración de Logging
# ---------------------------
# Asegurarse de que el directorio para el log exista
log_dir = os.path.dirname(LOG_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ---------------------------
# Clases y Funciones
# ---------------------------

class APIClient:
    """
    Cliente para interactuar con la API de creación de cuentas de mail.
    Configura la sesión de requests con reintentos y establece los encabezados.
    """
    def __init__(self, auth, planimail):
        self.auth = auth
        self.planimail = planimail
        self.url = API_URL
        self.headers = {
            'accept': 'application/json',
            'Authorization': self.auth,
            'Planimail': self.planimail,
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def create_mail_account(self, data):
        """
        Envía una solicitud POST a la API para crear una cuenta de mail.
        
        Args:
            data (dict): Diccionario con los datos de la cuenta.
        
        Returns:
            dict o None: Respuesta JSON si se creó la cuenta, None si hubo error.
        """
        try:
            response = self.session.post(self.url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            logging.info("Cuenta creada exitosamente para {}".format(data['email']))
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_message = "Error HTTP para {}: {} - {}".format(data['email'], response.status_code, response.text)
            logging.error(error_message, exc_info=True)
        except requests.exceptions.RequestException as e:
            error_message = "Excepción de solicitud para {}: {}".format(data['email'], str(e))
            logging.error(error_message, exc_info=True)
        except Exception as e:
            error_message = "Error inesperado para {}: {}".format(data['email'], str(e))
            logging.error(error_message, exc_info=True)
        return None

def generate_random_password(length=12):
    """
    Genera una contraseña aleatoria segura de la longitud especificada.
    
    Args:
        length (int): Longitud de la contraseña.
        
    Returns:
        str: Contraseña generada.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def validate_email(email):
    """
    Valida que el email tenga un formato correcto.
    
    Args:
        email (str): Dirección de email.
        
    Returns:
        bool: True si el email es válido, False en caso contrario.
    """
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_quota(quotamb):
    """
    Verifica que la cuota sea un entero positivo.
    
    Args:
        quotamb: Valor de la cuota.
        
    Returns:
        bool: True si la cuota es válida, False en caso contrario.
    """
    try:
        return int(quotamb) > 0
    except (TypeError, ValueError):
        return False

def normalize_email(email):
    """
    Convierte el email a minúsculas y elimina espacios en blanco.
    
    Args:
        email (str): Dirección de email.
        
    Returns:
        str: Email normalizado.
    """
    return email.strip().lower()

def read_csv_file(filename):
    """
    Lee el archivo CSV y lo transforma en una lista de diccionarios.
    
    Se asume que el archivo CSV está separado por ';' y tiene el siguiente formato:
        surname;name;email;password;[campo5];[campo6];[campo7]
    Se utilizan los primeros 4 campos.
    
    Args:
        filename (str): Ruta al archivo CSV.
        
    Returns:
        list: Lista de diccionarios con keys 'surname', 'name', 'email', 'password'.
    """
    rows = []
    try:
        with open(filename, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=';')
            for row in reader:
                if len(row) < 4:
                    continue
                row_dict = {
                    'surname': row[0].strip(),
                    'name': row[1].strip(),
                    'email': row[2].strip(),
                    'password': row[3].strip()
                }
                rows.append(row_dict)
    except FileNotFoundError:
        logging.error("Archivo {} no encontrado.".format(filename))
    except Exception as e:
        logging.error("Error al leer {}: {}".format(filename, str(e)))
    return rows

def process_account(account, api_client):
    """
    Procesa una cuenta: valida los datos, construye el diccionario
    y llama a la API para crear la cuenta.
    
    Args:
        account (dict): Diccionario con los datos de la cuenta.
        api_client (APIClient): Instancia del cliente API.
        
    Returns:
        str o None: Email de la cuenta si se creó exitosamente, None en caso de error.
    """
    email = normalize_email(account.get('email', ''))
    password = account.get('password', generate_random_password())
    # El CSV no incluye el parámetro "quotamb", se asigna el valor por defecto.
    quotamb = account.get('quotamb', DEFAULT_QUOTAMB)
    name = account.get('name', '')
    surname = account.get('surname', '')

    if not validate_email(email):
        logging.error("Email inválido: {}".format(email))
        return None

    if not validate_quota(quotamb):
        logging.error("Cuota inválida para {}: {}".format(email, quotamb))
        return None

    data = {
        "email": email,
        "password": password,
        "quotamb": int(quotamb),
        "name": name,
        "surname": surname
    }
    result = api_client.create_mail_account(data)
    time.sleep(1)  # Pausa entre peticiones para no saturar la API.
    return email if result is not None else None

def send_confirmation_email(created_accounts):
    """
    Envía un correo de confirmación con la lista de cuentas creadas.
    
    Args:
        created_accounts (list): Lista de emails de las cuentas creadas.
    """
    subject = "Confirmación de creación de cuentas de mail"
    if created_accounts:
        body = "Se crearon las siguientes cuentas de mail:\n\n" + "\n".join(created_accounts)
    else:
        body = "No se crearon cuentas de mail en esta ejecución."

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = MAIL_FROM
    # Los destinatarios se unen en una cadena separada por comas.
    msg['To'] = ", ".join(MAIL_TO)
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            logging.info("Correo de confirmación enviado correctamente.")
    except Exception as e:
        logging.error("Error al enviar correo de confirmación: {}".format(str(e)), exc_info=True)

def retrieve_latest_csv(remote_dir, local_dir):
    """
    Recupera el último archivo CSV desde el servidor remoto y lo copia
    al directorio local utilizando sshpass y scp.
    
    Args:
        remote_dir (str): Directorio remoto donde se encuentran los CSV.
        local_dir (str): Directorio local donde se guardará el CSV.
        
    Returns:
        str o None: Ruta local del archivo copiado o None en caso de error.
    """
    try:
        # Asegurarse de que el directorio local exista
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
            
        # Comando para obtener el nombre del último archivo CSV en el directorio remoto
        cmd = ("sshpass -p '{remote_pass}' ssh -o StrictHostKeyChecking=no -p {remote_port} {remote_user}@{remote_ip} "
               "'cd {remote_dir} && ls -1t *.csv 2>/dev/null | head -1'").format(
            remote_pass=REMOTE_PASS,
            remote_port=REMOTE_PORT,
            remote_user=REMOTE_USER,
            remote_ip=REMOTE_IP,
            remote_dir=remote_dir
        )
        output = subprocess.check_output(cmd, shell=True)
        latest_file = output.decode('utf-8').strip()
        if not latest_file:
            logging.info("No se encontró ningún archivo CSV en el servidor remoto.")
            return None
        logging.info("Último archivo CSV en remoto: {}".format(latest_file))
        # Construir las rutas remota y local para el archivo
        remote_path = os.path.join(remote_dir, latest_file)
        local_path = os.path.join(local_dir, latest_file)
        # Comando scp para copiar el archivo
        scp_cmd = ("sshpass -p '{remote_pass}' scp -o StrictHostKeyChecking=no -P {remote_port} "
                   "{remote_user}@{remote_ip}:{remote_path} {local_path}").format(
            remote_pass=REMOTE_PASS,
            remote_port=REMOTE_PORT,
            remote_user=REMOTE_USER,
            remote_ip=REMOTE_IP,
            remote_path=remote_path,
            local_path=local_path
        )
        subprocess.check_call(scp_cmd, shell=True)
        logging.info("Archivo {} copiado a {}".format(latest_file, local_path))
        return local_path
    except subprocess.CalledProcessError as cpe:
        logging.error("Error al recuperar el archivo CSV remoto: {}".format(str(cpe)))
        return None
    except Exception as e:
        logging.error("Error al recuperar el archivo CSV remoto: {}".format(str(e)))
        return None

def main():
    """
    Función principal: recupera el último CSV desde el servidor remoto, 
    procesa las cuentas del CSV y envía un correo de confirmación.
    """
    created_accounts = []

    # Recuperar el último CSV desde el servidor remoto y guardarlo en CSV_DIR
    local_csv = retrieve_latest_csv(REMOTE_CSV_DIR, CSV_DIR)
    if not local_csv:
        logging.info("No se pudo recuperar ningún archivo CSV desde el servidor remoto.")
        send_confirmation_email(created_accounts)
        return

    logging.info("Procesando archivo: {}".format(local_csv))
    accounts = read_csv_file(local_csv)
    if not accounts:
        logging.info("No se encontraron cuentas en {}".format(local_csv))
        send_confirmation_email(created_accounts)
        return

    api_client = APIClient(AUTHORIZATION, PLANIMAIL)
    for account in accounts:
        created = process_account(account, api_client)
        if created:
            created_accounts.append(created)

    send_confirmation_email(created_accounts)

if __name__ == "__main__":
    main()
