#  Archivo: backend/db.py
# ─────────────────────────────────────────
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv
from pathlib import Path
# Cargar variables desde .env
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / '.env')

def get_connection():
    """
    Retorna una conexión activa a la base de datos PostgreSQL.
    Las credenciales se leen desde el archivo .env
    """
    connection = psycopg2.connect(
        host     = os.getenv("DB_HOST"),
        port     = os.getenv("DB_PORT"),
        dbname   = os.getenv("DB_NAME"),
        user     = os.getenv("DB_USER"),
        password = os.getenv("DB_PASSWORD")
    )
    # Establecer zona horaria de México
    with connection.cursor() as cur:
        cur.execute("SET TIME ZONE 'America/Mexico_City'")
    connection.commit()
    return connection