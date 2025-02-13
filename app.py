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
import psycopg2

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_segura'  # Cambia esto en producción



@app.route('/admin/eliminar_registro/<int:id>', methods=['POST'])
def eliminar_registro(id):
    conn = get_db_connection ()
    conn.execute('DELETE FROM registros WHERE id = ?' , (id,))
    conn.commit ()
    conn.close()
    return redirect(url_for('admin'))  # Redirigir al panel de admin después de eliminar


def get_db_connection():
    DATABASE_URL = "postgresql://database_c07f_user:qRy1dJvExdCKQMFUUrNqJFvrXupP5ETs@dpg-cun45f2n91rc73ca3bag-a.oregon-postgres.render.com/database_c07f"
    
    conn = psycopg2.connect(DATABASE_URL)
    return conn  # No necesitas `row_factory` en PostgreSQL

# Inicialización de la base de datos
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Crear tabla de usuarios si no existe
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL,
                      role TEXT NOT NULL)''')
    
    # Crear tabla de registros si no existe
    cursor.execute('''CREATE TABLE IF NOT EXISTS registros (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      fecha TEXT NOT NULL,
                      hora_entrada TEXT,
                      hora_salida TEXT,
                      ubicacion TEXT,
                      foto TEXT,
                      FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Verificar si el usuario admin ya existe
    cursor.execute("SELECT COUNT(*) FROM users WHERE name = ?", ("admin",))
    if cursor.fetchone()[0] == 0:
        hashed_password = bcrypt.hashpw("Admin07".encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
        cursor.execute("INSERT INTO users (name, password, role) VALUES (?, ?, ?)", 
                       ("admin", hashed_password, "admin"))
    
    conn.commit()
    conn.close()

# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

# Ruta de inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    name = request.form['name']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        session['user_id'] = user['id']
        session['name'] = user['name']
        session['role'] = user['role']
        flash("Inicio de sesión exitoso", "success")
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

# Ruta para manejar Check-In y Check-Out
@app.route('/check', methods=['POST'])
def check():
    if 'user_id' not in session:
        flash("Debes iniciar sesión", "warning")
        return redirect(url_for('index'))
    zona_horaria = pytz.timezone('America/Mexico_City')
    
    check_type = request.form['check_type']
    location = request.form['location']
    photo = request.form['photo']
    ahora = datetime.now(zona_horaria)
    fecha = ahora.strftime('%Y-%m-%d')
    hora = ahora.strftime('%H:%M:%S')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if check_type == "Check-In":
        # Verificar si ya se registró el Check-In hoy
        cursor.execute("SELECT * FROM registros WHERE user_id = ? AND fecha = ?", (session['user_id'], fecha))
        if cursor.fetchone():
            flash("Ya has registrado tu entrada hoy", "warning")
        else:
            cursor.execute("INSERT INTO registros (user_id, fecha, hora_entrada, ubicacion, foto) VALUES (?, ?, ?, ?, ?)", 
                           (session['user_id'], fecha, hora, location, photo))
            flash("Entrada registrada con éxito", "success")
    elif check_type == "Check-Out":
        # Verificar si ya se registró el Check-Out hoy
        cursor.execute("SELECT * FROM registros WHERE user_id = ? AND fecha = ? AND hora_salida IS NOT NULL", (session['user_id'], fecha))
        if cursor.fetchone():
            flash("Ya has registrado tu salida hoy", "warning")
        else:
            cursor.execute("UPDATE registros SET hora_salida = ?, ubicacion = ?, foto = ? WHERE user_id = ? AND fecha = ?", 
                           (hora, location, photo, session['user_id'], fecha))
            flash("Salida registrada con éxito", "success")

    conn.commit()
    conn.close()
    flash(f"{check_type} registrado con éxito", "success")
    return redirect(url_for('dashboard'))

# Ruta del panel de administración
@app.route('/admin')
def admin():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener todos los usuarios
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    # Obtener todos los registros
    cursor.execute("SELECT * FROM registros")
    registros = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, registros=registros)

# Ruta para agregar usuarios (solo para admin)
@app.route('/admin/agregar_usuario', methods=['POST'])
def agregar_usuario():
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    name = request.form['user_name']
    password = request.form['user_password']
    role = "empleado"  # Por defecto, los nuevos usuarios son empleados

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar si el usuario ya existe
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    if cursor.fetchone():
        flash("El usuario ya existe", "danger")
        conn.close()
        return redirect(url_for('admin'))
    
    # Hashear la contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insertar el nuevo usuario en la base de datos
    cursor.execute("INSERT INTO users (name, password, role) VALUES (?, ?, ?)", 
                   (name, hashed_password, role))
    conn.commit()
    conn.close()
    
    flash("Usuario agregado con éxito", "success")
    return redirect(url_for('admin'))

# Ruta para eliminar usuarios
@app.route('/admin/eliminar_usuario/<int:user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Eliminar usuario
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    flash("Usuario eliminado con éxito", "success")
    return redirect(url_for('admin'))

# Ruta para cambiar contraseña
@app.route('/admin/cambiar_contraseña/<int:user_id>', methods=['POST'])
def cambiar_contraseña(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('index'))
    
    nueva_contraseña = request.form['nueva_contraseña']
    hashed_password = bcrypt.hashpw(nueva_contraseña.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Actualizar contraseña
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
    cursor.execute('''
        SELECT registros.id, users.name, registros.fecha, registros.hora_entrada, registros.hora_salida, registros.ubicacion
        FROM registros
        INNER JOIN users ON registros.user_id = users.id
    ''')
    registros = cursor.fetchall()
    conn.close()
    
    # Crear un archivo CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
    
    # Escribir la cabecera del CSV
    writer.writerow(["ID", "Nombre", "Fecha", "Hora Entrada", "Hora Salida", "Ubicación"])
    
    # Escribir los registros en el CSV
    for registro in registros:
        writer.writerow([
            registro['id'],
            registro['name'],
            registro['fecha'],
            registro['hora_entrada'],
            registro['hora_salida'],
            registro['ubicacion']
        ])
    
    # Preparar el archivo para descargar
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='registros_asistencia.csv'
    )



# Inicialización de la base de datos y ejecución de la aplicación
if __name__ == '__main__':
    init_db()
    app.run(debug=True)