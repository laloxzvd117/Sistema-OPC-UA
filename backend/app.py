from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import bcrypt
import re
import secrets
from db import get_connection

app = Flask(__name__,
            template_folder='../frontend',
            static_folder='../frontend')
app.secret_key = 'opc_ua_secret_key_2024'

# ─── ROLES PERMITIDOS (evita escalada de privilegios) ────────────────────────
ROLES_VALIDOS = {'Administrador', 'Empleado'}

# ─── HELPERS DE SEGURIDAD ────────────────────────────────────────────────────

def sanitizar_username(username: str) -> str:
    """Solo permite letras, números, puntos, guiones y guiones bajos."""
    return re.sub(r'[^\w.\-]', '', username)[:64]

def sanitizar_texto(texto: str, max_len: int = 120) -> str:
    """Elimina caracteres de control y limita longitud."""
    limpio = re.sub(r'[\x00-\x1f\x7f]', '', texto)
    return limpio[:max_len]

# ─── GESTIÓN DE SESIONES SERVER-SIDE ─────────────────────────────────────────

def crear_sesion_bd(id_usuario: int) -> str:
    """Genera un token único, lo guarda en SESION y lo retorna."""
    token = secrets.token_hex(32)           # 64 caracteres hexadecimales
    ip    = request.remote_addr or '0.0.0.0'
    try:
        conn = get_connection()
        cur  = conn.cursor()
        # Cierra cualquier sesión activa previa del mismo usuario
        cur.execute("""
            UPDATE "SESION"
            SET "Estado_Sesion" = 'cerrada', "Fecha_Fin" = NOW()
            WHERE "Id_Usuario" = %s AND "Estado_Sesion" = 'activa'
        """, (id_usuario,))
        # Crea la nueva sesión
        cur.execute("""
            INSERT INTO "SESION" ("Id_Usuario", "IP_Origen", "Estado_Sesion", "Token")
            VALUES (%s, %s, 'activa', %s)
        """, (id_usuario, ip, token))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass
    return token

def validar_sesion_bd() -> bool:
    """Verifica que el token en sesión exista y esté activo en BD.
    También verifica que el usuario siga activo (no desactivado por admin)."""
    token = session.get('token')
    if not token:
        return False
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("""
            SELECT s."Id_Sesion", u."Estado"
            FROM "SESION" s
            JOIN "USUARIO" u ON s."Id_Usuario" = u."Id_Usuario"
            WHERE s."Token" = %s AND s."Estado_Sesion" = 'activa'
        """, (token,))
        fila = cur.fetchone()
        cur.close()
        conn.close()
        # fila[1] = Estado del usuario (True = activo)
        return bool(fila and fila[1] is True)
    except Exception:
        return False

def cerrar_sesion_bd(token: str) -> None:
    """Marca la sesión como cerrada en BD."""
    if not token:
        return
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("""
            UPDATE "SESION"
            SET "Estado_Sesion" = 'cerrada', "Fecha_Fin" = NOW()
            WHERE "Token" = %s
        """, (token,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

def invalidar_sesiones_usuario(id_usuario: int) -> None:
    """Cierra todas las sesiones activas de un usuario.
    Se llama al eliminarlo o desactivarlo desde el panel de admin."""
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("""
            UPDATE "SESION"
            SET "Estado_Sesion" = 'cerrada', "Fecha_Fin" = NOW()
            WHERE "Id_Usuario" = %s AND "Estado_Sesion" = 'activa'
        """, (id_usuario,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

# ─── GUARDS DE ACCESO ─────────────────────────────────────────────────────────

def requiere_admin() -> bool:
    """Sesión válida en BD + rol Administrador.
    Validación completa usada en navegación de páginas y operaciones críticas."""
    return session.get('rol') == 'Administrador' and validar_sesion_bd()

def requiere_sesion() -> bool:
    """Sesión válida en BD + rol conocido.
    Validación completa usada en navegación de páginas."""
    return session.get('rol') in ROLES_VALIDOS and validar_sesion_bd()

def requiere_sesion_ligera() -> bool:
    """Solo verifica la cookie Flask, sin consulta a BD.
    Usada en APIs de polling frecuente (stats, estado linea) para minimizar latencia.
    La sesion server-side se valida en las rutas de pagina completa."""
    return session.get('rol') in ROLES_VALIDOS and bool(session.get('token'))

# ─── RUTAS DE AUTENTICACIÓN ───────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = sanitizar_username(request.form.get('username', '').strip())
        password = request.form.get('password', '').strip()

        if not username or not password:
            error = 'Usuario o contraseña incorrectos'
            return render_template('login.html', error=error)

        if len(password) > 128:
            error = 'Usuario o contraseña incorrectos'
            return render_template('login.html', error=error)

        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute("""
                SELECT u."Id_Usuario", u."Nombre", u."Contrasena", r."Nombre_Rol"
                FROM "USUARIO" u
                JOIN "ROL" r ON u."Id_Rol" = r."Id_Rol"
                WHERE u."Username" = %s AND u."Estado" = true
            """, (username,))
            usuario = cur.fetchone()
            cur.close()
            conn.close()

            print(f"[DEBUG] usuario encontrado: {usuario is not None}")
            if usuario:
                print(f"[DEBUG] intentando checkpw...")
                try:
                    pw_ok = bcrypt.checkpw(password.encode('utf-8'), usuario[2].encode('utf-8'))
                    print(f"[DEBUG] checkpw resultado: {pw_ok}")
                except Exception as ex:
                    print(f"[DEBUG] error en checkpw: {ex}")
                    pw_ok = False
            if usuario and bcrypt.checkpw(password.encode('utf-8'), usuario[2].encode('utf-8')):
                rol_bd = usuario[3]

                if rol_bd not in ROLES_VALIDOS:
                    error = 'Acceso no autorizado'
                    return render_template('login.html', error=error)

                # Genera token y registra sesión en BD
                token = crear_sesion_bd(usuario[0])

                session.clear()
                session.permanent = False
                session['id_usuario'] = usuario[0]
                session['nombre']     = sanitizar_texto(usuario[1])
                session['rol']        = rol_bd
                session['username']   = username
                session['token']      = token      # ← clave del sistema server-side

                if rol_bd == 'Administrador':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('empleado_dashboard'))
            else:
                error = 'Usuario o contraseña incorrectos'
        except Exception as e:
            print(f'[DEBUG LOGIN ERROR] {type(e).__name__}: {e}')
            error = f'Error: {type(e).__name__}: {e}'

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    cerrar_sesion_bd(session.get('token'))
    session.clear()
    return redirect(url_for('login'))

# ─── RUTAS ADMIN ─────────────────────────────────────────────────────────────

@app.route('/admin')
def admin_dashboard():
    if not requiere_admin():
        session.clear()
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html',
                           nombre=session.get('nombre'),
                           username_actual=session.get('username'))

@app.route('/admin/empleados')
def admin_empleados():
    if not requiere_admin():
        session.clear()
        return redirect(url_for('login'))
    return render_template('admin_empleados.html',
                           nombre=session.get('nombre'),
                           username_actual=session.get('username'))

# ─── RUTAS EMPLEADO ───────────────────────────────────────────────────────────

@app.route('/empleado')
def empleado_dashboard():
    if not requiere_sesion():
        session.clear()
        return redirect(url_for('login'))
    return render_template('empleado_dashboard.html',
                           nombre=session.get('nombre'),
                           rol=session.get('rol'))

# ─── API SIMULADA (línea de producción) ──────────────────────────────────────

estado_linea = {'encendida': False}
reportes = []

@app.route('/api/linea/estado', methods=['GET'])
def get_estado_linea():
    # Guard ligero: sin consulta a BD para minimizar latencia en polling
    if not requiere_sesion_ligera():
        return jsonify({'error': 'No autorizado', 'redirect': '/login'}), 403
    return jsonify(estado_linea)

@app.route('/api/linea/toggle', methods=['POST'])
def toggle_linea():
    # Guard completo: operacion critica, valida contra BD
    if not requiere_sesion():
        return jsonify({'error': 'No autorizado', 'redirect': '/login'}), 403
    estado_linea['encendida'] = not estado_linea['encendida']
    return jsonify(estado_linea)

@app.route('/api/reporte', methods=['POST'])
def crear_reporte():
    if not requiere_sesion():
        return jsonify({'error': 'No autorizado', 'redirect': '/login'}), 403
    data = request.get_json()
    reportes.append(data)
    return jsonify({'ok': True})

@app.route('/api/reportes', methods=['GET'])
def get_reportes():
    if not requiere_sesion():
        return jsonify({'error': 'No autorizado', 'redirect': '/login'}), 403
    return jsonify(reportes)

@app.route('/api/produccion/stats', methods=['GET'])
def get_stats():
    # Guard ligero: sin consulta a BD para minimizar latencia en polling
    if not requiere_sesion_ligera():
        return jsonify({'error': 'No autorizado', 'redirect': '/login'}), 403
    return jsonify({
        'total_frascos': 1284,
        'correctos': 1198,
        'defectuosos': 86,
        'linea_activa': estado_linea['encendida']
    })

# ─── API CRUD EMPLEADOS ───────────────────────────────────────────────────────

@app.route('/api/empleados', methods=['GET'])
def get_empleados():
    if not requiere_admin():
        return jsonify({'error': 'No autorizado'}), 403
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("""
            SELECT u."Id_Usuario", u."Nombre", u."Username", r."Nombre_Rol", u."Estado"
            FROM "USUARIO" u
            JOIN "ROL" r ON u."Id_Rol" = r."Id_Rol"
            ORDER BY u."Id_Usuario"
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        empleados = [
            {
                'id':      row[0],
                'nombre':  row[1],
                'usuario': row[2],
                'rol':     row[3],
                'estado':  'activo' if row[4] else 'inactivo'
            } for row in rows
        ]
        return jsonify(empleados)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/empleados', methods=['POST'])
def crear_empleado():
    if not requiere_admin():
        return jsonify({'error': 'No autorizado'}), 403
    try:
        data     = request.get_json()
        nombre   = sanitizar_texto(data.get('nombre', '').strip())
        usuario  = sanitizar_username(data.get('usuario', '').strip())
        password = data.get('password', '').strip()
        rol      = data.get('rol', 'Empleado')
        if rol not in ROLES_VALIDOS:
            return jsonify({'error': 'Rol no permitido'}), 400
        estado = data.get('estado', 'activo') == 'activo'

        if not nombre or not usuario or not password:
            return jsonify({'error': 'Nombre, usuario y contraseña son obligatorios'}), 400
        if len(password) > 128:
            return jsonify({'error': 'Contraseña demasiado larga'}), 400

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_connection()
        cur  = conn.cursor()
        cur.execute('SELECT "Id_Rol" FROM "ROL" WHERE "Nombre_Rol" = %s', (rol,))
        rol_row = cur.fetchone()
        if not rol_row:
            return jsonify({'error': 'Rol no encontrado en BD'}), 400

        cur.execute("""
            INSERT INTO "USUARIO" ("Nombre", "Username", "Contrasena", "Estado", "Id_Rol")
            VALUES (%s, %s, %s, %s, %s)
            RETURNING "Id_Usuario"
        """, (nombre, usuario, hashed, estado, rol_row[0]))
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True, 'id': new_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/empleados/<int:id_usuario>', methods=['PUT'])
def editar_empleado(id_usuario):
    if not requiere_admin():
        return jsonify({'error': 'No autorizado'}), 403
    try:
        data     = request.get_json()
        nombre   = sanitizar_texto(data.get('nombre', '').strip())
        usuario  = sanitizar_username(data.get('usuario', '').strip())
        rol      = data.get('rol', 'Empleado')
        if rol not in ROLES_VALIDOS:
            return jsonify({'error': 'Rol no permitido'}), 400
        estado   = data.get('estado', 'activo') == 'activo'
        password = data.get('password', '').strip()

        conn = get_connection()
        cur  = conn.cursor()
        cur.execute('SELECT "Id_Rol" FROM "ROL" WHERE "Nombre_Rol" = %s', (rol,))
        rol_row = cur.fetchone()
        if not rol_row:
            return jsonify({'error': 'Rol no encontrado en BD'}), 400

        if password:
            if len(password) > 128:
                return jsonify({'error': 'Contraseña demasiado larga'}), 400
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cur.execute("""
                UPDATE "USUARIO"
                SET "Nombre"=%s, "Username"=%s, "Contrasena"=%s, "Estado"=%s, "Id_Rol"=%s
                WHERE "Id_Usuario"=%s
            """, (nombre, usuario, hashed, estado, rol_row[0], id_usuario))
        else:
            cur.execute("""
                UPDATE "USUARIO"
                SET "Nombre"=%s, "Username"=%s, "Estado"=%s, "Id_Rol"=%s
                WHERE "Id_Usuario"=%s
            """, (nombre, usuario, estado, rol_row[0], id_usuario))

        conn.commit()
        cur.close()
        conn.close()

        # Si el usuario fue desactivado → cierra su sesión activa inmediatamente
        if not estado:
            invalidar_sesiones_usuario(id_usuario)

        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/empleados/<int:id_usuario>', methods=['DELETE'])
def eliminar_empleado(id_usuario):
    if not requiere_admin():
        return jsonify({'error': 'No autorizado'}), 403
    if id_usuario == session.get('id_usuario'):
        return jsonify({'error': 'No puedes eliminar tu propia cuenta'}), 400
    try:
        # Invalida sesión activa antes de eliminar (ON DELETE CASCADE la borrará de BD)
        invalidar_sesiones_usuario(id_usuario)

        conn = get_connection()
        cur  = conn.cursor()
        cur.execute('DELETE FROM "USUARIO" WHERE "Id_Usuario" = %s', (id_usuario,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # ── NOTA: BD REMOTA (descomenta cuando la VM de PostgreSQL esté en .30) ──
    # Actualmente db.py usa conexión local. Cuando la BD esté en la VM remota:
    #   1. En db.py cambia host='localhost' por host='192.168.10.30'
    #   2. Asegúrate de que PostgreSQL en la VM remota tenga en pg_hba.conf:
    #      host  all  all  192.168.10.0/24  md5
    #   3. En postgresql.conf: listen_addresses = '*'
    #   4. Abre el puerto 5432 en pfSense si las VMs están en segmentos distintos
    # ─────────────────────────────────────────────────────────────────────────
    app.run(debug=True, host='0.0.0.0', port=5000)