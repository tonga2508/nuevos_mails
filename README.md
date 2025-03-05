Instrucciones y Dependencias
Dependencias necesarias:
Python 3
Asegúrate de tener Python 3 instalado (se recomienda versión 3.5 o superior).
Puedes verificar la versión con:

bash
Copiar
python3 --version
Módulo requests
Este módulo se utiliza para realizar solicitudes HTTP a la API.
Para instalarlo, utiliza pip (si no lo tienes, instala python3-pip):

bash
Copiar
sudo apt update
sudo apt install python3-pip
python3 -m pip install requests
sshpass
Se utiliza para permitir la autenticación no interactiva vía SSH y SCP.
En sistemas basados en Debian/Ubuntu, puedes instalarlo con:

bash
Copiar
sudo apt update
sudo apt install sshpass
Configuración del Crontab:
Para que el script se ejecute automáticamente todos los días a las 23:30hs, sigue estos pasos:

Abre el crontab para el usuario correspondiente (o el root, según dónde se ejecutará):

bash
Copiar
crontab -e
Agrega la siguiente línea:

bash
Copiar
30 23 * * * /usr/bin/python3 /home/nuevosmails/nuevos_mails.py
Nota: Se especifica el intérprete de Python3 para asegurarse de que se ejecute con la versión correcta.

Guarda y cierra el editor.
El cron se encargará de ejecutar el script diariamente a las 23:30hs.
