import sys
sys.path.insert(0, '.')
from db import get_connection
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

conn = get_connection()
cur = conn.cursor()

# Insertar roles primero
cur.execute("""
    INSERT INTO "ROL" ("Nombre_Rol") VALUES ('admin'), ('empleado')
    ON CONFLICT DO NOTHING;
""")

# Insertar usuarios de prueba
usuarios = [
    ('Administrador', 'admin', hash_password('admin123'), 1),
    ('Juan Pérez',    'empleado1', hash_password('emp123'), 2),
]

for nombre, username, contrasena, id_rol in usuarios:
    cur.execute("""
        INSERT INTO "USUARIO" ("Nombre", "Username", "Contrasena", "Id_Rol")
        VALUES (%s, %s, %s, %s)
        ON CONFLICT ("Username") DO NOTHING;
    """, (nombre, username, contrasena, id_rol))

conn.commit()
cur.close()
conn.close()
print("Usuarios insertados correctamente")