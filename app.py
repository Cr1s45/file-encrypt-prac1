import io
from flask import Flask, get_flashed_messages, make_response, render_template, send_file, request, redirect, url_for, send_from_directory, flash, jsonify, abort
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from bson import ObjectId
from gridfs import GridFS
from io import BytesIO
from cryptography.fernet import Fernet
import re
from collections import Counter, defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = 'una_clave_secreta_muy_segura_y_unica'  

# Configuración de MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/file_encrypt_db"
mongo = PyMongo(app)
fs = GridFS(mongo.db) 

# Configuración de correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'onresolutefileencript@gmail.com'
app.config['MAIL_PASSWORD'] = 'nmkvufjchwcodhlv'  # NO tu contraseña normal
app.config['MAIL_DEFAULT_SENDER'] = ('FileEncript', 'onresolutefileencript@gmail.com')

mail = Mail(app)


# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"
app.config['REMEMBER_COOKIE_DURATION'] = 3600

# Clave para encriptación
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Modelo de usuario
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id  
        self.username = username

    @staticmethod
    def get(user_id):
        user_data = mongo.db.usuarios.find_one({'_id': ObjectId(user_id)})
        if not user_data:
            return None
        return User(user_id=user_id, username=user_data['username'])
    

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def convertir_tamaño(tamaño_bytes):
    """Convierte bytes a un formato legible (KB, MB, GB)"""
    for unidad in ['B', 'KB', 'MB', 'GB']:
        if tamaño_bytes < 1024:
            return f"{tamaño_bytes:.2f} {unidad}"
        tamaño_bytes /= 1024
    return f"{tamaño_bytes:.2f} TB"

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

def limpiar_nombre_archivo(texto):
    return re.sub(r'[<>:"/\\|?*]', '', texto)

# Ruta para el login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = mongo.db.usuarios.find_one({'username': username})
        
        if user_data and check_password_hash(user_data['password'], password):
            user_obj = User(user_id=str(user_data['_id']), username=user_data['username'])
            login_user(user_obj)
            

            print(f"Usuario autenticado: {user_data['username']}, Rol: {user_data.get('role')}")
            
        
            if user_data.get('role') == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('panel_user'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

# Ruta para registrar nuevos usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user') 
        existing_user = mongo.db.usuarios.find_one({'username': username})
        existing_user = mongo.db.usuarios.find_one({
            '$or': [{'username': username}, {'email': email}]
        })
        if existing_user:
            flash('El usuario o correo ya están registrados. Inicia sesión.', 'warning')
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
    
        mongo.db.usuarios.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password, 
            'role': role  
        })
       
        return redirect(url_for('login'))
    flashed_messages = get_flashed_messages(with_categories=True)
    filtered_messages = [(category, message) for category, message in flashed_messages 
                         if category in ['success', 'warning']]
    return render_template('register.html', messages=filtered_messages)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('home'))

#Ruta /forgot-password
from datetime import datetime, timedelta
import secrets
from flask import request, flash, redirect, url_for, render_template
from bson import ObjectId
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = mongo.db.usuarios.find_one({'email': email})

        if user:
            token = secrets.token_urlsafe(32)

            mongo.db.password_resets.insert_one({
                'user_id': str(user['_id']),
                'token': token,
                'expires_at': datetime.utcnow() + timedelta(minutes=15)
            })

            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message(
                subject="Recuperación de contraseña - FileEncript",
                recipients=[email],
                body=f"""Hola {user['username']},

Hemos recibido una solicitud para restablecer tu contraseña.

Puedes hacerlo usando este enlace (válido por 15 minutos):
{reset_link}

Si tú no solicitaste esto, ignora este mensaje.

Saludos,
Equipo FileEncript - OnResolute"""
            )
            
            try:
                print(">>> Intentando enviar el correo de recuperación...")
                mail.send(msg)
                print(">>> Correo de recuperación enviado correctamente")
                flash('Se ha enviado un enlace para restablecer tu contraseña.', 'info')
            except Exception as e:
                print(f">>> Error al enviar correo: {e}")
                flash(f'Error al enviar correo: {e}', 'danger')
        else:
            flash('Si el correo está registrado, recibirás un enlace.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')





#/reset-password/<token>
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_entry = mongo.db.password_resets.find_one({'token': token})

    if not reset_entry:
        flash('Enlace inválido o expirado.', 'danger')
        return redirect(url_for('login'))

    if datetime.utcnow() > reset_entry['expires_at']:
        mongo.db.password_resets.delete_one({'_id': reset_entry['_id']})
        flash('El enlace ha expirado. Solicita uno nuevo.', 'warning')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(request.url)

        hashed_password = generate_password_hash(new_password)
        user_id = reset_entry['user_id']

        mongo.db.usuarios.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'password': hashed_password}}
        )

        # Borrar el token usado
        mongo.db.password_resets.delete_one({'_id': reset_entry['_id']})

        flash('Tu contraseña ha sido actualizada correctamente.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Rutas principales
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/panel_user')
@login_required
def panel_user():
    if current_user.is_authenticated:
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        
        if user:
         
            archivos = list(mongo.db.archivos.find({'usuario': user['username']}))
            total_archivos = len(archivos)
            total_encriptados = len([archivo for archivo in archivos if archivo.get('encriptado', False)])
            total_no_encriptados = total_archivos - total_encriptados
            

            archivos_recientes = sorted(archivos, 
                                      key=lambda x: x['fecha_subida'], 
                                      reverse=True)[:5]
            
            return render_template('panel_user.html', 
                                 username=user['username'],
                                 user_role=user.get('role', 'user'),  
                                 total_archivos=total_archivos,
                                 total_encriptados=total_encriptados,
                                 total_no_encriptados=total_no_encriptados,
                                 archivos_recientes=archivos_recientes)
    
   
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    if current_user.is_authenticated:
    
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        
        if user and user.get('role') == 'admin':  
          
            total_archivos = mongo.db.archivos.count_documents({})
            total_usuarios = mongo.db.usuarios.count_documents({})
            total_encuestas = mongo.db.encuestas.count_documents({})
            
        
            archivos_recientes = list(mongo.db.archivos.find()
                                    .sort('fecha_subida', -1)
                                    .limit(5))
            
            return render_template('admin.html',
                                username=user['username'],
                                user_role=user['role'],
                                total_archivos=total_archivos,
                                total_usuarios=total_usuarios,
                                total_encuestas=total_encuestas,
                                archivos_recientes=archivos_recientes,
                                is_admin=True)
        
       
        flash('No tienes permisos para acceder a esta página', 'error')
        return redirect(url_for('panel_user'))
    return redirect(url_for('login'))

#Almacenamiento
@app.route('/admin/storage')
@login_required
def admin_storage():
    if current_user.is_authenticated:
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        if user and user.get('role') == 'admin':
            # Obtener todos los archivos
            archivos = list(mongo.db.archivos.find())
            almacenamiento = {}
            total_encriptados = 0
            total_no_encriptados = 0
            total_general = 0

            # Calcular el almacenamiento por usuario y total general
            for archivo in archivos:
                usuario = archivo.get('usuario')
                tamaño_bytes = archivo.get('tamaño', 0)
                encriptado = archivo.get('encriptado', False)

                if usuario:
                    almacenamiento[usuario] = almacenamiento.get(usuario, 0) + tamaño_bytes
                    total_general += tamaño_bytes

                    if encriptado:
                        total_encriptados += 1
                    else:
                        total_no_encriptados += 1

            # Función para convertir bytes a formato legible
            def formato_legible(tam_bytes):
                for unidad in ['B', 'KB', 'MB', 'GB']:
                    if tam_bytes < 1024:
                        return f"{tam_bytes:.2f} {unidad}"
                    tam_bytes /= 1024
                return f"{tam_bytes:.2f} TB"

            # Convertir a MB para el gráfico
            def bytes_a_mb(bytes_size):
                return bytes_size / (1024 * 1024)

            # Preparar datos para el gráfico
            labels_usuarios = list(almacenamiento.keys())
            datos_almacenamiento_mb = [bytes_a_mb(t) for t in almacenamiento.values()]
            total_general_mb = bytes_a_mb(total_general)

            # Formatear datos para mostrar
            almacenamiento_legible = {u: formato_legible(t) for u, t in almacenamiento.items()}
            archivos_con_formato = [
                {
                    'usuario': a.get('usuario'),
                    'nombre': a.get('nombre'),
                    'tamaño': formato_legible(a.get('tamaño', 0)),
                    'tamaño_bytes': a.get('tamaño', 0)
                } 
                for a in archivos
            ]

            return render_template('admin_storage.html',
                                almacenamiento=almacenamiento_legible,
                                archivos=archivos_con_formato,
                                labels_usuarios=labels_usuarios,
                                datos_almacenamiento=datos_almacenamiento_mb,
                                total_general=formato_legible(total_general),
                                total_general_mb=total_general_mb,
                                total_encriptados=total_encriptados,
                                total_no_encriptados=total_no_encriptados)
        else:
            flash('No tienes permisos de administrador.', 'error')
            return redirect(url_for('panel_user'))
    return redirect(url_for('login'))

@app.route('/admin/storage/pdf')
@login_required
def generate_storage_report():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
    if not user or user.get('role') != 'admin':
        flash('No tienes permisos de administrador.', 'error')
        return redirect(url_for('panel_user'))

    archivos = mongo.db.archivos.find()
    almacenamiento = {}

    for archivo in archivos:
        usuario = archivo.get('usuario')
        tamaño = archivo.get('tamaño', 0)
        if usuario:
            almacenamiento[usuario] = almacenamiento.get(usuario, 0) + tamaño

    # Crear PDF
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("Reporte de Almacenamiento")
    width, height = letter

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, height - 50, "Reporte de Almacenamiento por Usuario")

    pdf.setFont("Helvetica", 12)
    y = height - 90
    for usuario, tam in almacenamiento.items():
        pdf.drawString(50, y, f"Usuario: {usuario} - Almacenamiento: {round(tam / 1024, 2)} KB")
        y -= 20
        if y < 50:
            pdf.showPage()
            y = height - 50

    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=reporte_almacenamiento.pdf'
    return response

# Termina aqui lo de almacenamiento


@app.route('/archive')
@login_required
def archive():
    try:
     
        user_data = mongo.db.usuarios.find_one({'username': current_user.username})
        if not user_data:
            flash('Usuario no encontrado', 'error')
            return redirect(url_for('panel_user'))
        
      
        archivos = list(mongo.db.archivos.find({'usuario': current_user.username}))
        
        return render_template(
            'archive.html',
            archivos=archivos,
            username=current_user.username,
            user_role=user_data.get('role', 'user'), 
            convertir_tamaño=convertir_tamaño
        )
    except Exception as e:
        app.logger.error(f"Error al cargar archivos: {str(e)}")
        flash('Error al cargar los archivos', 'error')
        return redirect(url_for('panel_user'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No se seleccionó archivo', 'error')
        return redirect(url_for('archive'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Nombre de archivo vacío', 'error')
        return redirect(url_for('archive'))
    
    try:
        filename = secure_filename(file.filename)
        file_data = file.read()
        
      
        file_id = fs.put(
            BytesIO(file_data),
            filename=filename,
            content_type=file.content_type  
        )
        
      
        mongo.db.archivos.insert_one({
            'nombre': filename,
            'file_id': file_id,
            'fecha_subida': datetime.now(),
            'tamaño': len(file_data),
            'encriptado': False,  
            'usuario': current_user.username,
            'content_type': file.content_type  
        })
        
        flash('Archivo subido correctamente', 'success')
        return redirect(url_for('archive'))
    
    except Exception as e:
        flash(f'Error al subir archivo: {str(e)}', 'error')
        return redirect(url_for('archive'))
    
# Ruta para ver archivos
@app.route('/view/<file_id>')
@login_required
def view_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            abort(404, description="Archivo no encontrado o no tienes permisos")
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        # Desencriptar si es necesario
        if archivo['encriptado']:
            file_data = cipher_suite.decrypt(file_data)
        
        # Crear un objeto BytesIO con los datos del archivo
        file_stream = BytesIO(file_data)
        file_stream.seek(0)
        
        # Enviar el archivo con el tipo MIME correcto
        return send_file(
            file_stream,
            mimetype=archivo.get('content_type', 'application/octet-stream'),
            as_attachment=False,
            download_name=archivo['nombre']
        )
    
    except Exception as e:
        app.logger.error(f"Error al ver archivo {file_id}: {str(e)}")
        abort(404, description="Error al procesar el archivo")

# Ruta para descargar archivos
@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            abort(404, description="Archivo no encontrado o no tienes permisos")
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        # Desencriptar si es necesario
        if archivo['encriptado']:
            file_data = cipher_suite.decrypt(file_data)
        
        # Crear un objeto BytesIO con los datos del archivo
        file_stream = BytesIO(file_data)
        file_stream.seek(0)
        
        # Enviar el archivo como descarga
        return send_file(
            file_stream,
            mimetype=archivo.get('content_type', 'application/octet-stream'),
            as_attachment=True,
            download_name=archivo['nombre']
        )
    
    except Exception as e:
        app.logger.error(f"Error al descargar archivo {file_id}: {str(e)}")
        abort(404, description="Error al descargar el archivo")

# Ruta para encriptar/desencriptar archivos
@app.route('/toggle_encrypt/<file_id>', methods=['POST'])
@login_required
def toggle_encrypt(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        if archivo['encriptado']:
            # Desencriptar el archivo
            file_data = cipher_suite.decrypt(file_data)
            new_status = False
            message = 'Archivo desencriptado correctamente'
        else:
            # Encriptar el archivo
            file_data = cipher_suite.encrypt(file_data)
            new_status = True
            message = 'Archivo encriptado correctamente'
        
        # Eliminar el archivo viejo de GridFS
        fs.delete(archivo['file_id'])
        
        # Subir el nuevo archivo (encriptado/desencriptado) a GridFS
        new_file_id = fs.put(BytesIO(file_data), 
                          filename=archivo['nombre'],
                          content_type=archivo['content_type'])
        
        # Actualizar los metadatos en MongoDB (IMPORTANTE: incluir encriptado)
        result = mongo.db.archivos.update_one(
            {'_id': ObjectId(file_id)},
            {'$set': {
                'file_id': new_file_id,
                'encriptado': new_status,  # Este campo debe actualizarse
                'tamaño': len(file_data),
                'fecha_subida': datetime.now()  # Actualizar fecha de modificación
            }}
        )
        
        # Verificar que la actualización fue exitosa
        if result.modified_count == 0:
            raise Exception("No se pudo actualizar el estado en la base de datos")
        
        return jsonify({
            'success': True, 
            'message': message, 
            'encriptado': new_status
        })
    
    except Exception as e:
        app.logger.error(f"Error al cambiar encriptación {file_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error al procesar archivo: {str(e)}'
        }), 500

@app.route('/delete/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        # Eliminar el archivo de GridFS
        fs.delete(archivo['file_id'])
        
        # Eliminar el registro de MongoDB
        result = mongo.db.archivos.delete_one({'_id': ObjectId(file_id)})
        
        if result.deleted_count == 1:
            return jsonify({
                'success': True, 
                'message': 'Archivo eliminado correctamente'
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'No se pudo eliminar el archivo'
            }), 500
    
    except Exception as e:
        app.logger.error(f"Error al eliminar archivo {file_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error al eliminar archivo: {str(e)}'
        }), 500

# Rutas de encuestas
@app.route('/survey')
def survey():
    return render_template('survey.html')

@app.route('/re_answer')
@login_required  
def re_answer():
    try:

        encuestas = list(mongo.db.encuestas.find())
        

        datos_encuestas = []
        
        for encuesta in encuestas:
  
            for pregunta in encuesta.get('preguntas', []):
                datos_encuestas.append({
                    'pregunta': pregunta['texto'],
                    'tipo': pregunta['tipo'],
                    'respuesta': pregunta['respuesta'],
                    'fecha': encuesta['fecha_creacion'].strftime('%Y-%m-%d %H:%M') if 'fecha_creacion' in encuesta else 'Sin fecha'
                })
        
        # Agrupar respuestas por pregunta
        preguntas_respuestas = {}
        for dato in datos_encuestas:
            if dato['pregunta'] not in preguntas_respuestas:
                preguntas_respuestas[dato['pregunta']] = []  
            preguntas_respuestas[dato['pregunta']].append({
                'respuesta': dato['respuesta'],
                'fecha': dato['fecha'],
                'tipo': dato['tipo']
            })
        
        return render_template('re_answer.html', preguntas_respuestas=preguntas_respuestas)
    
    except Exception as e:
        print(f"Error al obtener respuestas: {str(e)}")
        flash('Error al cargar las respuestas', 'error')
        return redirect(url_for('admin'))


@app.route('/generate_report')
@login_required
def generate_report():

    pass

@app.route('/generate_pptx_report')
@login_required
def generate_pptx_report():

    pass

@app.route('/generate_xls_report')
@login_required
def generate_xls_report():
   
    pass


@app.route('/submit_survey', methods=['POST'])
@login_required
def submit_survey():
    try:
       
        tiempo_espera = request.form.get('pregunta1', '0')  # Numérico (minutos)
        mejora = request.form.get('pregunta2', 'No especificado')  # Abierta
        calificacion_servicio = request.form.get('pregunta3', '0')  # Escala 1-5
        recomendacion = request.form.get('pregunta4', 'No especificado')  # Opción
        soporte_tecnico = request.form.get('pregunta5', 'No especificado')  # Opción

        # Crear estructura de la encuesta
        encuesta_data = {
            'usuario_id': ObjectId(current_user.id),
            'nombre': 'Encuesta de satisfacción',
            'preguntas': [
                {
                    'texto': '¿Cuál ha sido el tiempo de espera? (en minutos)',
                    'tipo': 'numerico',
                    'respuesta': int(tiempo_espera) if tiempo_espera.isdigit() else 0,
                    'orden': 1
                },
                {
                    'texto': '¿Qué te gustaría mejorar?',
                    'tipo': 'abierta',
                    'respuesta': mejora,
                    'orden': 2
                },
                {
                    'texto': '¿Cómo calificarías nuestro servicio?',
                    'tipo': 'escala',
                    'respuesta': int(calificacion_servicio) if calificacion_servicio.isdigit() else 0,
                    'orden': 3
                },
                {
                    'texto': '¿Recomendarías nuestro servicio?',
                    'tipo': 'opcion',
                    'respuesta': recomendacion,
                    'orden': 4
                },
                {
                    'texto': '¿Cómo calificarías el soporte técnico?',
                    'tipo': 'opcion',
                    'respuesta': soporte_tecnico,
                    'orden': 5
                }
            ],
            'fecha_creacion': datetime.now()
        }

        # Guardar en la base de datos
        mongo.db.encuestas.insert_one(encuesta_data)
        flash('Encuesta enviada correctamente', 'success')
        return redirect(url_for('panel_user'))

    except Exception as e:
        print(f"Error al procesar encuesta: {str(e)}")
        flash('Error al enviar la encuesta', 'error')
        return redirect(url_for('survey'))

@app.route('/usuarios_archivos')
@login_required
def usuarios_archivos():
    if current_user.is_authenticated:
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        if user and user.get('role') == 'admin':
            # Obtener todos los usuarios
            usuarios = list(mongo.db.usuarios.find())

            # Para cada usuario, obtener estadísticas de archivos
            usuarios_info = []
            for u in usuarios:
                archivos = list(mongo.db.archivos.find({'usuario': u['username']}))
                total_archivos = len(archivos)
                archivos_encriptados = len([a for a in archivos if a.get('encriptado', False)])
                archivos_no_encriptados = total_archivos - archivos_encriptados
                total_tamaño = sum(a.get('tamaño', 0) for a in archivos)
                usuarios_info.append({
                    'username': u['username'],
                    'total_archivos': total_archivos,
                    'archivos_encriptados': archivos_encriptados,
                    'archivos_no_encriptados': archivos_no_encriptados,
                    'total_tamaño': total_tamaño
                })

                # --- NUEVO BLOQUE PARA GRÁFICO ---

            hoy = datetime.now().date()
            conteo_por_dia = defaultdict(int)

            fecha_inicio = hoy - timedelta(days=6)  # últimos 7 días incluyendo hoy

            # Obtener archivos subidos en los últimos 7 días
            archivos_recientes = list(mongo.db.archivos.find({
                'fecha_subida': {'$gte': datetime.combine(fecha_inicio, datetime.min.time())}
            }))

            for archivo in archivos_recientes:
                fecha = archivo['fecha_subida'].date()
                conteo_por_dia[fecha] += 1

            # Crear listas ordenadas para etiquetas y datos
            fechas_ordenadas = [fecha_inicio + timedelta(days=i) for i in range(7)]
            labels = [fecha.strftime('%d %b') for fecha in fechas_ordenadas]
            data = [conteo_por_dia.get(fecha, 0) for fecha in fechas_ordenadas]

            return render_template('usuarios_archivos.html',
                                   usuarios=usuarios_info,
                                   username=user['username'],
                                   chart_labels=labels,
                                    chart_data=data)
        else:
            flash('No tienes permisos para acceder a esta página', 'error')
            return redirect(url_for('panel_user'))
    return redirect(url_for('login'))



if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('reports'):
        os.makedirs('reports')
    app.run(debug=True)