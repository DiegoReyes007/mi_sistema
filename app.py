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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registros WHERE id = %s', (id,))
    conn.commit()
    cursor.close()
    conn.close()

def get_db_connection():
    DATABASE_URL = "postgresql://database_c07f_user:qRy1dJvExdCKQMFUUrNqJFvrXupP5ETs@dpg-cun45f2n91rc73ca3bag-a.oregon-postgres.render.com/database_c07f"
    
    conn = psycopg2.connect(DATABASE_URL)
    return conn  # No necesitas `row_factory` en PostgreSQL

# Inicialización de la base de datos
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id SERIAL PRIMARY KEY,
                      name TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL,
                      role TEXT NOT NULL)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS registros (
                      id SERIAL PRIMARY KEY,
                      user_id INTEGER NOT NULL,
                      fecha TEXT NOT NULL,
                      hora_entrada TEXT,
                      hora_salida TEXT,
                      ubicacion TEXT,
                      foto TEXT,
                      FOREIGN KEY (user_id) REFERENCES users (id))''')

    cursor.execute("SELECT COUNT(*) FROM users WHERE name = %s", ("admin",))
    if cursor.fetchone()[0] == 0:
        hashed_password = bcrypt.hashpw("Admin07".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (name, password, role) VALUES (%s, %s, %s)", 
                       ("admin", hashed_password, "admin"))
    
    conn.commit()
    conn.close()


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
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        session['user_id'] = user[0]
        session['name'] = user[1]
        session['role'] = user[3]
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
    
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

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

    if check_type == "Check-In":
        cursor.execute("INSERT INTO registros (user_id, fecha, hora_entrada, ubicacion, foto) VALUES (%s, %s, %s, %s, %s)", 
                       (session['user_id'], fecha, hora, location, photo))
    elif check_type == "Check-Out":
        cursor.execute("UPDATE registros SET hora_salida = %s, ubicacion = %s, foto = %s WHERE user_id = %s AND fecha = %s", 
                       (hora, location, photo, session['user_id'], fecha))

    conn.commit()
    cursor.close()
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
    
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

    if cursor.fetchone():
        flash("El usuario ya existe", "danger")
        conn.close()
        return redirect(url_for('admin'))
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    cursor.execute("INSERT INTO users (name, password, role) VALUES (%s, %s, %s)", 
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
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
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
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
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
        registro[0],  # ID
        registro[1],  # Nombre
        registro[2],  # Fecha
        registro[3],  # Hora Entrada
        registro[4],  # Hora Salida
        registro[5]   # Ubicación
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