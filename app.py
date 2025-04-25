from flask import Flask, render_template, request, redirect, session, flash, send_file, url_for
import sqlite3
import bcrypt
import base64
import io
import csv
from datetime import datetime
import pandas as pd
import os
import pytz
import calendar


app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_segura'  # Cambia esto en producción

# Función para obtener la conexión a la base de datos
def get_db_connection():
   
    conn = sqlite3.connect('database.db')  # Conexión a SQLite
    conn.row_factory = sqlite3.Row  # Esto convierte las filas en diccionarios
    return conn

# Inicialización de la base de datos
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Crear las tablas si no existen
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL,
                      role TEXT NOT NULL)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS registros (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      fecha TEXT NOT NULL,
                      hora_entrada TEXT,
                      hora_salida TEXT,
                      ubicacion TEXT,
                      foto TEXT,
                      FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS bitacora (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                     usuario TEXT,
                     accion TEXT,
                     fecha TEXT
                                )''')

    # Comprobar si el usuario admin existe, si no, lo crea
    cursor.execute("SELECT COUNT(*) FROM users WHERE name = 'admin'")
    if cursor.fetchone()[0] == 0:
        hashed_password = bcrypt.hashpw("Admin07".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (name, password, role) VALUES (?, ?, ?)", 
                       ("admin", hashed_password, "admin"))
    
    conn.commit()
    conn.close()

@app.route('/admin/eliminar_registro/<int:id>', methods=['POST'])
def eliminar_registro(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registros WHERE id = ?', (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Registro eliminado con éxito", "success")
    return redirect(url_for('admin'))

@app.route('/admin/eliminar_todos', methods=['POST'])
def eliminar_todos_registros():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registros')  # Elimina todos los registros
    conn.commit()
     # Registrar en bitácora
    accion = 'Eliminación total de registros'
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO bitacora (accion, fecha) VALUES (?, ?)', (accion, fecha))
    conn.commit()

    cursor.close()
    conn.close()
    flash("Todos los registros han sido eliminados con éxito", "success")
    return redirect(url_for('admin'))



# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    name = request.form['name']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        session['user_id'] = user[0]
        session['name'] = user[1]
        session['role'] = user[3]
        flash("Inicio de sesión exitoso", "success")
        if user[1] == "admin":
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('dashboard'))
    
    flash("Usuario o contraseña incorrectos", "danger")
    return redirect(url_for('index'))

# Ruta del dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Debes iniciar sesión", "warning")
        return redirect(url_for('index'))
    return render_template('dashboard.html', name=session['name'])

# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada", "info")
    return redirect(url_for('index'))

# Ruta de registro de usuarios (solo para admin)
@app.route('/register', methods=['POST'])
def register():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    name = request.form['name']
    password = request.form['password']
    role = request.form['role']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))

    if cursor.fetchone():
        flash("El usuario ya existe", "danger")
        conn.close()
        return redirect(url_for('index'))
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute("INSERT INTO users (name, password, role) VALUES (?, ?, ?)", 
                   (name, hashed_password, role))
    conn.commit()
    conn.close()
    
    flash("Usuario registrado con éxito", "success")
    return redirect(url_for('index'))
# Desarrollado por DIEGO ARTURO HERNANDEZ REYES - DAOSTEK
@app.route('/check', methods=['POST'])
def check():
    if 'user_id' not in session:
        flash("Debes iniciar sesión", "warning")
        return redirect(url_for('index'))
    
    zona_horaria = pytz.timezone('America/Mexico_City')
    ahora = datetime.now(zona_horaria)
    fecha = ahora.strftime('%Y-%m-%d')
    hora = ahora.strftime('%H:%M:%S')
    
    check_type = request.form['check_type']
    location = request.form['location']
    photo = request.form['photo']
    
    conn = get_db_connection()
    cursor = conn.cursor()

   
    # Verifica si ya existe un registro para hoy
    cursor.execute("SELECT hora_entrada, hora_salida FROM registros WHERE user_id = ? AND fecha = ?", 
                   (session['user_id'], fecha))
    registro = cursor.fetchone()

    if check_type == "Check-In":
        if registro and registro['hora_entrada']:
            flash("Ya realizaste tu Check-In hoy", "warning")
        else:
            if registro:
                # Ya existe un registro para hoy, actualiza solo la hora_entrada
                cursor.execute("UPDATE registros SET hora_entrada = ?, ubicacion = ?, foto = ? WHERE user_id = ? AND fecha = ?", 
                               (hora, location, photo, session['user_id'], fecha))
            else:
                # No hay registro hoy, inserta uno nuevo
                cursor.execute("INSERT INTO registros (user_id, fecha, hora_entrada, ubicacion, foto) VALUES (?, ?, ?, ?, ?)", 
                               (session['user_id'], fecha, hora, location, photo))
            conn.commit()
            

    elif check_type == "Check-Out":
        if registro and registro['hora_salida']:
            flash("Ya realizaste tu Check-Out hoy", "warning")
        elif not registro:
            flash("Primero debes hacer Check-In antes del Check-Out", "danger")
        else:
            cursor.execute("UPDATE registros SET hora_salida = ?, ubicacion = ?, foto = ? WHERE user_id = ? AND fecha = ?", 
                           (hora, location, photo, session['user_id'], fecha))
            conn.commit()
            flash("Check-Out registrado con éxito", "success")

    conn.commit()
    cursor.close()
    conn.close()
    
   
    return redirect(url_for('dashboard'))

# Ruta del panel de administración
@app.route('/admin')
def admin():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    conn.row_factory = sqlite3.Row

    # Obtener todos los usuarios
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    # Obtener todos los registros
    cursor.execute("SELECT * FROM registros")
    cursor.execute('''
        SELECT registros.id,users.id AS user_id, users.name AS user_name, registros.fecha, registros.hora_entrada, registros.hora_salida, registros.ubicacion, registros.foto
        FROM registros
        JOIN users ON registros.user_id = users.id
    ''')
    registros = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, registros=registros)

@app.route('/admin/agregar_usuario', methods=['POST'])
def agregar_usuario():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    name = request.form['user_name']
    password = request.form['user_password']
    role = "empleado"

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))

    if cursor.fetchone():
        flash("El usuario ya existe", "danger")
        conn.close()
        return redirect(url_for('admin'))
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    cursor.execute("INSERT INTO users (name, password, role) VALUES (?, ?, ?)", 
                   (name, hashed_password, role))
    conn.commit()
    conn.close()
    
    flash("Usuario agregado con éxito", "success")
    return redirect(url_for('admin'))

@app.route('/admin/eliminar_usuario/<int:user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM registros WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    flash("Usuario eliminado con éxito", "success")
    return redirect(url_for('admin'))

@app.route('/admin/cambiar_contraseña/<int:user_id>', methods=['POST'])
def cambiar_contraseña(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    nueva_contraseña = request.form['nueva_contraseña']
    hashed_password = bcrypt.hashpw(nueva_contraseña.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    conn.close()
    flash("Contraseña actualizada con éxito", "success")
    return redirect(url_for('admin'))

    
        
# Ruta para exportar registros a CSV
@app.route('/export')
def export_csv():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener todos los registros
    cursor.execute('''SELECT registros.id, users.name, registros.fecha, registros.hora_entrada, registros.hora_salida, registros.ubicacion
                      FROM registros
                      INNER JOIN users ON registros.user_id = users.id''')
    registros = cursor.fetchall()
    conn.close()
    
    # Crear un archivo CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
    
    # Escribir la cabecera del CSV
    writer.writerow(["ID", "Nombre", "Fecha", "Hora Entrada", "Hora Salida", "Ubicación"])
    
    # Escribir los registros en el CSV
    for registro in registros:
        writer.writerow([registro[0], registro[1], registro[2], registro[3], registro[4], registro[5]])
    
    mes_actual = calendar.month_name[datetime.now().month]
    nombre_archivo = f'registros_{mes_actual}.csv'

    # Preparar el archivo para descargar
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=nombre_archivo
    )



def borrar_visitas_y_fotos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registros')  # Elimina todos los registros
    conn.commit()
     # Registrar en bitácora
    accion = 'Eliminación total de registros'
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO bitacora (accion, fecha) VALUES (?, ?)', (accion, fecha))
    conn.commit()

    cursor.close()
    conn.close()
    flash("Todos los registros han sido eliminados con éxito", "success")
    return redirect(url_for('admin'))

@app.route('/borrar_visitas', methods=['POST'])
def borrar_visitas():
    borrar_visitas_y_fotos()

# Ruta para exportar registros a CSV
@app.route('/descargar_respaldo')
def descargar_respaldo():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener todos los registros
    cursor.execute('''SELECT registros.id, users.name, registros.fecha, registros.hora_entrada, registros.hora_salida, registros.ubicacion
                      FROM registros
                      INNER JOIN users ON registros.user_id = users.id''')
    registros = cursor.fetchall()
    conn.close()
    
    # Crear un archivo CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
    
    # Escribir la cabecera del CSV
    writer.writerow(["ID", "Nombre", "Fecha", "Hora Entrada", "Hora Salida", "Ubicación"])
    
    # Escribir los registros en el CSV
    for registro in registros:
        writer.writerow([registro[0], registro[1], registro[2], registro[3], registro[4], registro[5]])
    
    mes_actual = calendar.month_name[datetime.now().month]
    nombre_archivo = f'registros_{mes_actual}.csv'

    # Preparar el archivo para descargar
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=nombre_archivo
    )

# Inicialización de la base de datos
init_db()



if __name__ == '__main__':
    app.run(debug=True)
