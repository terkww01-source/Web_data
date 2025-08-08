data = json.loads(message)
                    message_type = data.get("type")
                    
                    if message_type == "client_register":
                        client_id = data.get("client_id")
                        if client_id:
                            # Register client
                            client_manager.register_client(client_id, websocket=websocket)
                            db_manager.register_client(data)
                            self.clients[client_id] = websocket
                            
                            # Send acknowledgment
                            response = {
                                "type": "registration_ack",
                                "status": "success",
                                "server_time": datetime.now().isoformat()
                            }
                            await websocket.send(json.dumps(response))
                            
                            # Notify web interface
                            socketio.emit('client_connected', {
                                'client_id': client_id,
                                'client_info': data
                            })
                            
                            logger.info(f"Client registered via WebSocket: {client_id}")
                    
                    elif message_type == "heartbeat":
                        client_id = data.get("client_id")
                        if client_id:
                            system_status = data.get("system_status")
                            client_manager.update_heartbeat(client_id, system_status)
                            
                            # Send heartbeat response
                            response = {
                                "type": "heartbeat_ack",
                                "server_time": datetime.now().isoformat()
                            }
                            await websocket.send(json.dumps(response))
                    
                    elif message_type == "command_response":
                        # Handle command response from client
                        command_id = data.get("command_id")
                        client_id = data.get("client_id")
                        result = data.get("result")
                        status = data.get("status", "completed")
                        error = data.get("error")
                        
                        # Update command in database
                        db_manager.update_command_result(command_id, result, status, error)
                        
                        # Notify web interface
                        socketio.emit('command_completed', {
                            'command_id': command_id,
                            'client_id': client_id,
                            'result': result,
                            'status': status,
                            'error': error
                        })
                        
                        logger.info(f"Command {command_id} completed for client {client_id}")
                    
                    else:
                        logger.warning(f"Unknown message type: {message_type}")
                
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON from client: {message}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WebSocket connection closed for client {client_id}")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            # Cleanup
            if client_id:
                client_manager.unregister_client(client_id)
                if client_id in self.clients:
                    del self.clients[client_id]
                
                # Notify web interface
                socketio.emit('client_disconnected', {
                    'client_id': client_id
                })
    
    async def send_command_to_client(self, client_id, command):
        """Send command to specific client"""
        if client_id in self.clients:
            try:
                websocket = self.clients[client_id]
                await websocket.send(json.dumps(command))
                return True
            except Exception as e:
                logger.error(f"Error sending command to {client_id}: {e}")
                return False
        return False

# Global WebSocket handler
ws_handler = WebSocketHandler()

# Authentication helper
def require_auth(f):
    """Decorator to require authentication"""
    from functools import wraps
    
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    
    return decorated

# Web Routes
@app.route('/')
@require_auth
def dashboard():
    """Main dashboard page"""
    clients = db_manager.get_clients(active_only=True)
    recent_backups = db_manager.get_backups(limit=10)
    recent_commands = db_manager.get_commands(limit=20)
    
    # Get connected clients info
    connected_clients_info = []
    for client in clients:
        client_id = client['id']
        is_online = client_manager.is_client_online(client_id)
        client['is_online'] = is_online
        
        if is_online:
            client_info = client_manager.get_client(client_id)
            if client_info:
                client['last_heartbeat'] = client_info['last_heartbeat'].isoformat()
                client['connected_duration'] = str(datetime.now() - client_info['connected_at'])
        
        connected_clients_info.append(client)
    
    dashboard_stats = {
        'total_clients': len(clients),
        'online_clients': len([c for c in connected_clients_info if c.get('is_online', False)]),
        'total_backups': len(recent_backups),
        'pending_commands': len([c for c in recent_commands if c['status'] == 'pending'])
    }
    
    return render_template('dashboard.html', 
                         clients=connected_clients_info,
                         recent_backups=recent_backups,
                         recent_commands=recent_commands,
                         stats=dashboard_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == CONFIG['ADMIN_USERNAME'] and password == CONFIG['ADMIN_PASSWORD']:
            session['authenticated'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            session['last_activity'] = datetime.now().isoformat()
            
            db_manager.log_event('INFO', f'User {username} logged in', category='auth')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            db_manager.log_event('WARNING', f'Failed login attempt for {username}', category='auth')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.clear()
    db_manager.log_event('INFO', f'User {username} logged out', category='auth')
    return redirect(url_for('login'))

@app.route('/clients')
@require_auth
def clients_page():
    """Clients management page"""
    clients = db_manager.get_clients()
    
    # Add online status
    for client in clients:
        client['is_online'] = client_manager.is_client_online(client['id'])
    
    return render_template('clients.html', clients=clients)

@app.route('/client/<client_id>')
@require_auth
def client_detail(client_id):
    """Client detail page"""
    clients = db_manager.get_clients()
    client = next((c for c in clients if c['id'] == client_id), None)
    
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('clients_page'))
    
    client['is_online'] = client_manager.is_client_online(client_id)
    
    backups = db_manager.get_backups(client_id=client_id)
    commands = db_manager.get_commands(client_id=client_id, limit=50)
    
    return render_template('client_detail.html', 
                         client=client, 
                         backups=backups,
                         commands=commands)

@app.route('/backups')
@require_auth
def backups_page():
    """Backups page"""
    client_id = request.args.get('client_id')
    backups = db_manager.get_backups(client_id=client_id, limit=100)
    clients = db_manager.get_clients()
    
    return render_template('backups.html', 
                         backups=backups, 
                         clients=clients,
                         selected_client=client_id)

@app.route('/commands')
@require_auth
def commands_page():
    """Commands page"""
    client_id = request.args.get('client_id')
    status = request.args.get('status')
    commands = db_manager.get_commands(client_id=client_id, status=status, limit=100)
    clients = db_manager.get_clients()
    
    return render_template('commands.html',
                         commands=commands,
                         clients=clients,
                         selected_client=client_id,
                         selected_status=status)

# API Routes
@app.route('/api/clients')
@require_auth
def api_clients():
    """API: Get all clients"""
    clients = db_manager.get_clients()
    
    # Add online status and connection info
    for client in clients:
        client_id = client['id']
        client['is_online'] = client_manager.is_client_online(client_id)
        
        if client['is_online']:
            client_info = client_manager.get_client(client_id)
            if client_info:
                client['connection_info'] = {
                    'connected_at': client_info['connected_at'].isoformat(),
                    'last_heartbeat': client_info['last_heartbeat'].isoformat()
                }
    
    return jsonify(clients)

@app.route('/api/client/<client_id>/command', methods=['POST'])
@require_auth
def api_send_command(client_id):
    """API: Send command to client"""
    try:
        command_data = request.json
        command_id = str(uuid.uuid4())
        
        command = {
            "id": command_id,
            "type": command_data.get("type"),
            "client_id": client_id,
            **command_data
        }
        
        # Save command to database
        db_manager.save_command(command)
        
        # Try to send via WebSocket first
        success = False
        if client_id in ws_handler.clients:
            try:
                # Use asyncio to send the command
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                success = loop.run_until_complete(
                    ws_handler.send_command_to_client(client_id, command)
                )
                loop.close()
            except Exception as e:
                logger.error(f"Error sending command via WebSocket: {e}")
        
        if not success:
            # Add to command queue as fallback
            client_manager.add_command_to_queue(client_id, command)
        
        db_manager.log_event('INFO', f'Command {command["type"]} sent to client {client_id}', 
                           client_id=client_id, category='command')
        
        return jsonify({
            "status": "success",
            "command_id": command_id,
            "message": "Command sent successfully"
        })
        
    except Exception as e:
        logger.error(f"Error sending command: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/client/<client_id>/backup', methods=['POST'])
@require_auth
def api_create_backup(client_id):
    """API: Create backup for client"""
    try:
        backup_type = request.json.get("backup_type", "full")
        upload_to_server = request.json.get("upload", True)
        
        command = {
            "type": "create_backup",
            "backup_type": backup_type,
            "upload": upload_to_server
        }
        
        return api_send_command(client_id)
        
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    """API: Upload file from client"""
    try:
        upload_data = request.json
        client_id = upload_data.get("client_id")
        file_name = upload_data.get("file_name")
        file_data = upload_data.get("file_data")  # Base64 encoded
        
        if not all([client_id, file_name, file_data]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Decode file data
        try:
            decoded_data = base64.b64decode(file_data)
        except Exception as e:
            return jsonify({"error": "Invalid base64 data"}), 400
        
        # Create upload directory
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], client_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = secure_filename(file_name)
        stored_filename = f"{timestamp}_{safe_filename}"
        file_path = os.path.join(upload_dir, stored_filename)
        
        # Write file
        with open(file_path, 'wb') as f:
            f.write(decoded_data)
        
        # Calculate file hash
        file_hash = hashlib.sha256(decoded_data).hexdigest()
        
        # Save file info to database
        file_info = {
            "client_id": client_id,
            "original_path": upload_data.get("file_path", ""),
            "stored_path": file_path,
            "filename": file_name,
            "file_size": len(decoded_data),
            "file_hash": file_hash,
            "mime_type": upload_data.get("mime_type", "")
        }
        
        db_manager.save_file(file_info)
        
        logger.info(f"File uploaded: {file_name} from client {client_id}")
        
        return jsonify({
            "status": "success",
            "file_path": file_path,
            "file_size": len(decoded_data),
            "file_hash": file_hash
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/download/<path:file_path>')
@require_auth
def api_download_file(file_path):
    """API: Download file"""
    try:
        # Security: ensure file is in upload folder
        full_path = os.path.abspath(file_path)
        upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
        
        if not full_path.startswith(upload_folder):
            return jsonify({"error": "Access denied"}), 403
        
        if not os.path.exists(full_path):
            return jsonify({"error": "File not found"}), 404
        
        return send_file(full_path, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
@require_auth
def api_stats():
    """API: Get dashboard statistics"""
    try:
        clients = db_manager.get_clients()
        backups = db_manager.get_backups(limit=1000)
        commands = db_manager.get_commands(limit=1000)
        
        online_clients = [c for c in clients if client_manager.is_client_online(c['id'])]
        
        # Calculate statistics
        stats = {
            "clients": {
                "total": len(clients),
                "online": len(online_clients),
                "offline": len(clients) - len(online_clients)
            },
            "backups": {
                "total": len(backups),
                "completed": len([b for b in backups if b['status'] == 'completed']),
                "failed": len([b for b in backups if b['status'] == 'failed']),
                "in_progress": len([b for b in backups if b['status'] == 'in_progress'])
            },
            "commands": {
                "total": len(commands),
                "pending": len([c for c in commands if c['status'] == 'pending']),
                "completed": len([c for c in commands if c['status'] == 'completed']),
                "failed": len([c for c in commands if c['status'] == 'failed'])
            }
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({"error": str(e)}), 500

# SocketIO Events
@socketio.on('connect')
@require_auth
def handle_connect():
    """Handle SocketIO connection"""
    logger.info(f"SocketIO client connected: {request.sid}")
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
@require_auth
def handle_disconnect():
    """Handle SocketIO disconnection"""
    logger.info(f"SocketIO client disconnected: {request.sid}")

@socketio.on('join_client_room')
@require_auth
def handle_join_client_room(data):
    """Join room for specific client updates"""
    client_id = data.get('client_id')
    if client_id:
        join_room(f"client_{client_id}")
        emit('joined_room', {'client_id': client_id})

@socketio.on('leave_client_room')
@require_auth
def handle_leave_client_room(data):
    """Leave client room"""
    client_id = data.get('client_id')
    if client_id:
        leave_room(f"client_{client_id}")
        emit('left_room', {'client_id': client_id})

# Background tasks
def cleanup_task():
    """Background cleanup task"""
    while True:
        try:
            # Cleanup inactive clients
            client_manager.cleanup_inactive_clients()
            
            # Cleanup old data
            db_manager.cleanup_old_data()
            
            logger.info("Cleanup task completed")
            
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
        
        # Sleep for 5 minutes
        time.sleep(300)

# HTML Templates (embedded for simplicity)
HTML_TEMPLATES = {
    'base.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}System Control Dashboard{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .sidebar { background-color: #343a40; min-height: 100vh; }
        .sidebar .nav-link { color: #fff; }
        .sidebar .nav-link:hover { background-color: #495057; }
        .sidebar .nav-link.active { background-color: #007bff; }
        .status-online { color: #28a745; }
        .status-offline { color: #dc3545; }
        .card-stats { border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <nav class="col-md-2 col-lg-2 sidebar">
                <div class="position-sticky pt-3">
                    <h5 class="text-white mb-3">Control Panel</h5>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('dashboard') }}">
                                <i class="fas fa-tachometer-alt"></i> Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('clients_page') }}">
                                <i class="fas fa-desktop"></i> Clients
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('backups_page') }}">
                                <i class="fas fa-archive"></i> Backups
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('commands_page') }}">
                                <i class="fas fa-terminal"></i> Commands
                            </a>
                        </li>
                    </ul>
                    <hr class="text-white">
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('logout') }}">
                                <i class="fas fa-sign-out-alt"></i> Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>
            
            <main class="col-md-10 col-lg-10 ms-sm-auto px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">{% block header %}Dashboard{% endblock %}</h1>
                </div>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.4/socket.io.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
    ''',
    
    'login.html': '''
{% extends "base.html" %}

{% block title %}Login - System Control Dashboard{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h4 class="mb-0">Login</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
    ''',
    
    'dashboard.html': '''
{% extends "base.html" %}

{% block content %}
<!-- Stats Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card card-stats">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <p class="card-category">Total Clients</p>
                        <p class="card-title">{{ stats.total_clients }}</p>
                    </div>
                    <div class="icon">
                        <i class="fas fa-desktop fa-2x text-primary"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card card-stats">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <p class="card-category">Online Clients</p>
                        <p class="card-title">{{ stats.online_clients }}</p>
                    </div>
                    <div class="icon">
                        <i class="fas fa-circle fa-2x text-success"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card card-stats">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <p class="card-category">Total Backups</p>
                        <p class="card-title">{{ stats.total_backups }}</p>
                    </div>
                    <div class="icon">
                        <i class="fas fa-archive fa-2x text-info"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card card-stats">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <p class="card-category">Pending Commands</p>
                        <p class="card-title">{{ stats.pending_commands }}</p>
                    </div>
                    <div class="icon">
                        <i class="fas fa-clock fa-2x text-warning"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Connected Clients -->
<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5>Connected Clients</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Client Name</th>
                                <th>Hostname</th>
                                <th>OS</th>
                                <th>Last Seen</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for client in clients %}
                            <tr>
                                <td>
                                    {% if client.is_online %}
                                        <i class="fas fa-circle status-online"></i> Online
                                    {% else %}
                                        <i class="fas fa-circle status-offline"></i> Offline
                                    {% endif %}
                                </td>
                                <td>{{ client.name }}</td>
                                <td>{{ client.hostname }}</td>
                                <td>{{ client.os_info }}</td>
                                <td>{{ client.last_seen }}</td>
                                <td>
                                    <a href="{{ url_for('client_detail', client_id=client.id) }}" class="btn btn-sm btn-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                    {% if client.is_online %}
                                    <button class="btn btn-sm btn-success" onclick="createBackup('{{ client.id }}')">
                                        <i class="fas fa-archive"></i> Backup
                                    </button>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5>Recent Activity</h5>
            </div>
            <div class="card-body">
                <div class="list-group list-group-flush">
                    {% for backup in recent_backups[:5] %}
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">Backup {{ backup.backup_type }}</h6>
                            <small>{{ backup.created_at }}</small>
                        </div>
                        <p class="mb-1">Client: {{ backup.client_id[:8] }}...</p>
                        <small class="text-muted">Status: {{ backup.status }}</small>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    const socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
    });
    
    socket.on('client_connected', function(data) {
        console.log('Client connected:', data);
        location.reload(); // Simple refresh for now
    });
    
    socket.on('client_disconnected', function(data) {
        console.log('Client disconnected:', data);
        location.reload(); // Simple refresh for now
    });
    
    function createBackup(clientId) {
        if (confirm('Create backup for this client?')) {
            fetch(`/api/client/${clientId}/backup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    backup_type: 'full',
                    upload: true
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert('Backup command sent successfully!');
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error sending backup command');
            });
        }
    }
</script>
{% endblock %}
    '''
}

# Create templates directory and write templates
def setup_templates():
    """Setup HTML templates"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    for template_name, template_content in HTML_TEMPLATES.items():
        template_path = os.path.join(templates_dir, template_name)
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)

async def start_websocket_server():
    """Start WebSocket server in background"""
    try:
        await ws_handler.start_server()
        logger.info("WebSocket server started successfully")
    except Exception as e:
        logger.error(f"Failed to start WebSocket server: {e}")

def create_app():
    """Create and configure Flask app"""
    # Setup templates
    setup_templates()
    
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Start cleanup task
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    
    return app

if __name__ == '__main__':
    # Create app
    app = create_app()
    
    # Start WebSocket server in background
    def start_ws_server():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_websocket_server())
        loop.run_forever()
    
    ws_thread = threading.Thread(target=start_ws_server, daemon=True)
    ws_thread.start()
    
    # Start Flask app with SocketIO
    logger.info(f"Starting server on port {CONFIG['WS_PORT']}")
    socketio.run(
        app,
        host='0.0.0.0',
        port=CONFIG['WS_PORT'],
        debug=CONFIG['DEBUG'],
        allow_unsafe_werkzeug=True
    )#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import asyncio
import logging
import sqlite3
import zipfile
import base64
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import uuid
import threading
from urllib.parse import urlparse, parse_qs

# Web framework imports
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
import websockets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Configuration
CONFIG = {
    "SECRET_KEY": os.environ.get("SECRET_KEY", "your-secret-key-change-this"),
    "DATABASE_PATH": "dashboard.db",
    "UPLOAD_FOLDER": "uploads",
    "MAX_CONTENT_LENGTH": 500 * 1024 * 1024,  # 500MB
    "WS_PORT": int(os.environ.get("PORT", 5000)),
    "DEBUG": os.environ.get("FLASK_ENV") == "development",
    "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", "admin"),
    "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "admin123"),  # Change this!
    "SESSION_TIMEOUT": 3600,  # 1 hour
    "CLIENT_TIMEOUT": 300,  # 5 minutes
    "MAX_CLIENTS": 100,
    "BACKUP_RETENTION_DAYS": 30,
    "LOG_RETENTION_DAYS": 7
}

# Setup logging
logging.basicConfig(
    level=logging.INFO if not CONFIG["DEBUG"] else logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['MAX_CONTENT_LENGTH'] = CONFIG["MAX_CONTENT_LENGTH"]
app.config['UPLOAD_FOLDER'] = CONFIG["UPLOAD_FOLDER"]

# SocketIO setup
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    ping_timeout=60,
    ping_interval=25
)

# Global variables
connected_clients = {}
client_data = {}
websocket_clients = {}

class DatabaseManager:
    """Database manager for storing client data and backups"""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or CONFIG["DATABASE_PATH"]
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clients table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS clients (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        hostname TEXT,
                        os_info TEXT,
                        arch TEXT,
                        python_version TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'offline',
                        system_info TEXT,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Backup data table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS backups (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        backup_type TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'in_progress',
                        size INTEGER DEFAULT 0,
                        file_count INTEGER DEFAULT 0,
                        metadata TEXT,
                        file_paths TEXT,
                        error_message TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients (id)
                    )
                ''')
                
                # Commands table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS commands (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        command_type TEXT NOT NULL,
                        command_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        executed_at TIMESTAMP,
                        status TEXT DEFAULT 'pending',
                        result TEXT,
                        error TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients (id)
                    )
                ''')
                
                # Files table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS files (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        backup_id TEXT,
                        original_path TEXT NOT NULL,
                        stored_path TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        file_size INTEGER,
                        file_hash TEXT,
                        mime_type TEXT,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_sensitive BOOLEAN DEFAULT 0,
                        tags TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients (id),
                        FOREIGN KEY (backup_id) REFERENCES backups (id)
                    )
                ''')
                
                # Logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        category TEXT,
                        details TEXT
                    )
                ''')
                
                # User sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address TEXT,
                        user_agent TEXT,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def register_client(self, client_info):
        """Register or update client information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO clients 
                    (id, name, hostname, os_info, arch, python_version, last_seen, status, system_info)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'online', ?)
                ''', (
                    client_info.get("client_id"),
                    client_info.get("client_name", "Unknown"),
                    client_info.get("hostname", ""),
                    client_info.get("os", ""),
                    client_info.get("arch", ""),
                    client_info.get("python_version", ""),
                    json.dumps(client_info)
                ))
                
                conn.commit()
                logger.info(f"Client registered: {client_info.get('client_id')}")
                
        except Exception as e:
            logger.error(f"Error registering client: {e}")
    
    def update_client_status(self, client_id, status, system_status=None):
        """Update client status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                update_data = [status, client_id]
                query = "UPDATE clients SET status = ?, last_seen = CURRENT_TIMESTAMP"
                
                if system_status:
                    query += ", system_info = ?"
                    update_data.insert(-1, json.dumps(system_status))
                
                query += " WHERE id = ?"
                
                cursor.execute(query, update_data)
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating client status: {e}")
    
    def get_clients(self, active_only=False):
        """Get all clients"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM clients"
                if active_only:
                    query += " WHERE is_active = 1"
                query += " ORDER BY last_seen DESC"
                
                cursor.execute(query)
                
                columns = [description[0] for description in cursor.description]
                clients = []
                
                for row in cursor.fetchall():
                    client = dict(zip(columns, row))
                    # Parse JSON fields
                    if client['system_info']:
                        try:
                            client['system_info'] = json.loads(client['system_info'])
                        except:
                            client['system_info'] = {}
                    clients.append(client)
                
                return clients
                
        except Exception as e:
            logger.error(f"Error getting clients: {e}")
            return []
    
    def save_backup(self, backup_info):
        """Save backup information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO backups
                    (id, client_id, backup_type, status, size, file_count, metadata, file_paths)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    backup_info.get("backup_id"),
                    backup_info.get("client_id"),
                    backup_info.get("backup_type", "full"),
                    backup_info.get("status", "completed"),
                    backup_info.get("size", 0),
                    backup_info.get("file_count", 0),
                    json.dumps(backup_info),
                    json.dumps(backup_info.get("backup_files", []))
                ))
                
                conn.commit()
                logger.info(f"Backup saved: {backup_info.get('backup_id')}")
                
        except Exception as e:
            logger.error(f"Error saving backup: {e}")
    
    def get_backups(self, client_id=None, limit=50):
        """Get backup history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM backups"
                params = []
                
                if client_id:
                    query += " WHERE client_id = ?"
                    params.append(client_id)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                
                columns = [description[0] for description in cursor.description]
                backups = []
                
                for row in cursor.fetchall():
                    backup = dict(zip(columns, row))
                    # Parse JSON fields
                    if backup['metadata']:
                        try:
                            backup['metadata'] = json.loads(backup['metadata'])
                        except:
                            backup['metadata'] = {}
                    if backup['file_paths']:
                        try:
                            backup['file_paths'] = json.loads(backup['file_paths'])
                        except:
                            backup['file_paths'] = []
                    backups.append(backup)
                
                return backups
                
        except Exception as e:
            logger.error(f"Error getting backups: {e}")
            return []
    
    def save_command(self, command_info):
        """Save command to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO commands
                    (id, client_id, command_type, command_data, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    command_info.get("id", str(uuid.uuid4())),
                    command_info.get("client_id"),
                    command_info.get("type"),
                    json.dumps(command_info),
                    "pending"
                ))
                
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            logger.error(f"Error saving command: {e}")
            return None
    
    def update_command_result(self, command_id, result, status="completed", error=None):
        """Update command result"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE commands 
                    SET status = ?, result = ?, error = ?, executed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (status, json.dumps(result) if result else None, error, command_id))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating command result: {e}")
    
    def get_commands(self, client_id=None, status=None, limit=100):
        """Get commands history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM commands WHERE 1=1"
                params = []
                
                if client_id:
                    query += " AND client_id = ?"
                    params.append(client_id)
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                
                columns = [description[0] for description in cursor.description]
                commands = []
                
                for row in cursor.fetchall():
                    command = dict(zip(columns, row))
                    # Parse JSON fields
                    if command['command_data']:
                        try:
                            command['command_data'] = json.loads(command['command_data'])
                        except:
                            command['command_data'] = {}
                    if command['result']:
                        try:
                            command['result'] = json.loads(command['result'])
                        except:
                            command['result'] = {}
                    commands.append(command)
                
                return commands
                
        except Exception as e:
            logger.error(f"Error getting commands: {e}")
            return []
    
    def save_file(self, file_info):
        """Save file information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO files
                    (id, client_id, backup_id, original_path, stored_path, filename, 
                     file_size, file_hash, mime_type, is_sensitive, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_info.get("id", str(uuid.uuid4())),
                    file_info.get("client_id"),
                    file_info.get("backup_id"),
                    file_info.get("original_path"),
                    file_info.get("stored_path"),
                    file_info.get("filename"),
                    file_info.get("file_size", 0),
                    file_info.get("file_hash"),
                    file_info.get("mime_type"),
                    file_info.get("is_sensitive", False),
                    file_info.get("tags", "")
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error saving file info: {e}")
    
    def log_event(self, level, message, client_id=None, category=None, details=None):
        """Log event to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO logs (client_id, level, message, category, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (client_id, level, message, category, json.dumps(details) if details else None))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error logging event: {e}")
    
    def cleanup_old_data(self):
        """Cleanup old data based on retention policies"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Cleanup old backups
                backup_cutoff = datetime.now() - timedelta(days=CONFIG["BACKUP_RETENTION_DAYS"])
                cursor.execute('''
                    DELETE FROM backups 
                    WHERE created_at < ? AND status = 'completed'
                ''', (backup_cutoff,))
                
                # Cleanup old logs
                log_cutoff = datetime.now() - timedelta(days=CONFIG["LOG_RETENTION_DAYS"])
                cursor.execute('DELETE FROM logs WHERE timestamp < ?', (log_cutoff,))
                
                # Cleanup inactive sessions
                session_cutoff = datetime.now() - timedelta(seconds=CONFIG["SESSION_TIMEOUT"])
                cursor.execute('''
                    UPDATE user_sessions 
                    SET is_active = 0 
                    WHERE last_activity < ?
                ''', (session_cutoff,))
                
                conn.commit()
                logger.info("Old data cleanup completed")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

class ClientManager:
    """Manage connected clients"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.clients = {}
        self.client_locks = {}
        
    def register_client(self, client_id, websocket=None, socketio_sid=None):
        """Register a new client connection"""
        client_info = {
            "id": client_id,
            "websocket": websocket,
            "socketio_sid": socketio_sid,
            "connected_at": datetime.now(),
            "last_heartbeat": datetime.now(),
            "status": "online",
            "command_queue": [],
            "pending_commands": {}
        }
        
        self.clients[client_id] = client_info
        self.client_locks[client_id] = threading.Lock()
        
        logger.info(f"Client registered: {client_id}")
        return client_info
    
    def unregister_client(self, client_id):
        """Unregister client connection"""
        if client_id in self.clients:
            del self.clients[client_id]
            
        if client_id in self.client_locks:
            del self.client_locks[client_id]
            
        # Update database
        self.db.update_client_status(client_id, "offline")
        logger.info(f"Client unregistered: {client_id}")
    
    def update_heartbeat(self, client_id, system_status=None):
        """Update client heartbeat"""
        if client_id in self.clients:
            self.clients[client_id]["last_heartbeat"] = datetime.now()
            
            if system_status:
                self.clients[client_id]["system_status"] = system_status
                # Update database
                self.db.update_client_status(client_id, "online", system_status)
    
    def get_client(self, client_id):
        """Get client information"""
        return self.clients.get(client_id)
    
    def get_all_clients(self):
        """Get all connected clients"""
        return list(self.clients.values())
    
    def is_client_online(self, client_id):
        """Check if client is online"""
        if client_id not in self.clients:
            return False
        
        client = self.clients[client_id]
        last_heartbeat = client["last_heartbeat"]
        timeout = timedelta(seconds=CONFIG["CLIENT_TIMEOUT"])
        
        return datetime.now() - last_heartbeat < timeout
    
    def add_command_to_queue(self, client_id, command):
        """Add command to client queue"""
        if client_id in self.clients:
            with self.client_locks.get(client_id, threading.Lock()):
                self.clients[client_id]["command_queue"].append(command)
                return True
        return False
    
    def get_pending_commands(self, client_id):
        """Get pending commands for client"""
        if client_id in self.clients:
            with self.client_locks.get(client_id, threading.Lock()):
                commands = self.clients[client_id]["command_queue"].copy()
                self.clients[client_id]["command_queue"].clear()
                return commands
        return []
    
    def cleanup_inactive_clients(self):
        """Remove inactive clients"""
        current_time = datetime.now()
        timeout = timedelta(seconds=CONFIG["CLIENT_TIMEOUT"])
        
        inactive_clients = []
        for client_id, client_info in self.clients.items():
            if current_time - client_info["last_heartbeat"] > timeout:
                inactive_clients.append(client_id)
        
        for client_id in inactive_clients:
            self.unregister_client(client_id)

# Initialize managers
db_manager = DatabaseManager()
client_manager = ClientManager(db_manager)

class WebSocketHandler:
    """Handle WebSocket connections from clients"""
    
    def __init__(self):
        self.server = None
        self.clients = {}
    
    async def start_server(self, host="0.0.0.0", port=None):
        """Start WebSocket server"""
        if port is None:
            port = CONFIG["WS_PORT"] + 1  # Use different port for WebSocket
        
        logger.info(f"Starting WebSocket server on {host}:{port}")
        
        self.server = await websockets.serve(
            self.handle_client,
            host,
            port,
            ping_interval=30,
            ping_timeout=10
        )
        
        return self.server
    
    async def handle_client(self, websocket, path):
        """Handle individual client connection"""
        client_id = None
        
        try:
            logger.info(f"New WebSocket connection from {websocket.remote_address}")
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    message_type
