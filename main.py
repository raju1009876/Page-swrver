from flask import Flask, request, render_template_string, session, redirect, url_for
import requests
from threading import Thread, Event
import time
import random
import string
from collections import defaultdict
from datetime import datetime
import pytz
import re
import os  # Add this import

app = Flask(__name__)
app.secret_key = "SuperSecretKey2025"

USERNAME = "vampire boy raj"
PASSWORD = "vampire rulex"
ADMIN_USERNAME = "raj mishra"
ADMIN_PASSWORD = "vampire rulex"

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64)',
    'Referer': 'https://www.google.com/'
}

stop_events = {}
threads = {}
task_count = 0
user_tasks = defaultdict(list)
task_info = {}
MAX_TASKS = 10000

ist = pytz.timezone('Asia/Kolkata')

def extract_token_from_cookies(cookies_text):
    """Extract EAAD token from Facebook cookies"""
    try:
        lines = cookies_text.strip().split('\n')
        cookies_dict = {}
        
        for line in lines:
            if '=' in line:
                parts = line.split('=', 1)
                key = parts[0].strip()
                value = parts[1].strip()
                cookies_dict[key] = value
        
        required_cookies = ['c_user', 'xs']
        if not all(cookie in cookies_dict for cookie in required_cookies):
            return None, "Missing required cookies (c_user and xs)"
        
        req_session = requests.Session()
        for key, value in cookies_dict.items():
            req_session.cookies.set(key, value)
        
        response = req_session.get('https://www.facebook.com/', headers=headers)
        if 'login' in response.url:
            return None, "Invalid cookies - redirecting to login"
        
        token_patterns = [
            r'EAAD\w+',
            r'accessToken":"([^"]+)"',
            r'access_token=([^&]+)'
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, response.text)
            if matches:
                return matches[0], "Token extracted successfully"
        
        dev_response = req_session.get('https://developers.facebook.com/tools/debug/accesstoken/', headers=headers)
        for pattern in token_patterns:
            matches = re.findall(pattern, dev_response.text)
            if matches:
                return matches[0], "Token extracted successfully"
        
        return None, "Token not found in page source"
    
    except Exception as e:
        return None, f"Error extracting token: {str(e)}"

def format_uptime(seconds):
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes {int(seconds % 60)} seconds"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)} hours {int(minutes)} minutes"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{int(days)} days {int(hours)} hours"

def format_time_ago(timestamp):
    now = datetime.now(ist)
    diff = now - timestamp
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    else:
        days = int(seconds // 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = False
            return redirect(url_for('send_message'))
        elif username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        return 'Invalid Username or Password!'
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body { text-align: center; padding: 100px; background: #121212; color: white; }
            input { padding: 10px; margin: 5px; width: 250px; }
            button { padding: 10px; background: red; color: white; border: none; }
        </style>
    </head>
    <body>
        <h2>Login to Access</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Enter Username" required><br>
            <input type="password" name="password" placeholder="Enter Password" required><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    '''

@app.route('/home', methods=['GET', 'POST'])
def send_message():
    if not session.get('logged_in') or session.get('is_admin'):
        return redirect(url_for('login'))

    username = session.get('username')
    
    if request.method == 'POST':
        if task_count >= MAX_TASKS:
            return 'Monthly Task Limit Reached!'

        input_type = request.form.get('inputType')
        access_tokens = []
        
        if input_type == 'token':
            token = request.form.get('singleToken').strip()
            if token:
                access_tokens = [token]
        elif input_type == 'cookies':
            cookies_text = request.form.get('cookies').strip()
            if cookies_text:
                token, message = extract_token_from_cookies(cookies_text)
                if token:
                    access_tokens = [token]
                else:
                    return f'Failed to extract token from cookies: {message}'
        
        if not access_tokens:
            return 'No valid token provided'
        
        thread_id = request.form.get('threadId').strip()
        hatersname = request.form.get('hatersname').strip()
        lastname = request.form.get('lastname').strip()
        time_interval = int(request.form.get('time'))

        if 'txtFile' in request.files:
            txt_file = request.files['txtFile']
            if txt_file.filename != '':
                messages = txt_file.read().decode().splitlines()
            else:
                messages_text = request.form.get('messages', '')
                messages = messages_text.splitlines() if messages_text else ['Test message']
        else:
            messages_text = request.form.get('messages', '')
            messages = messages_text.splitlines() if messages_text else ['Test message']

        task_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        stop_events[task_id] = Event()
        thread = Thread(target=send_messages, args=(access_tokens, thread_id, hatersname, lastname, time_interval, messages, task_id, username))
        threads[task_id] = thread
        thread.start()
        
        user_tasks[username].append(task_id)
        global task_count
        task_count += 1
        return f'Task started with ID: {task_id}'

    user_task_count = len(user_tasks.get(username, []))
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
      <title>Offline Tool</title>
      <style>
        body {{ text-align: center; padding: 50px; background: #121212; color: white; }}
        input, select, button, textarea {{ margin: 5px; padding: 10px; }}
        .input-group {{ margin: 15px 0; }}
        .token-input {{ display: block; }}
        .cookies-input {{ display: none; }}
      </style>
      <script>
        function toggleInput() {{
            var inputType = document.getElementById('inputType').value;
            document.getElementById('tokenInput').style.display = inputType === 'token' ? 'block' : 'none';
            document.getElementById('cookiesInput').style.display = inputType === 'cookies' ? 'block' : 'none';
        }}
      </script>
    </head>
    <body>
      <h2>Your Running Tasks: {user_task_count}</h2>
      <h3>Global Tasks: {task_count} / {MAX_TASKS}</h3>
      <form method="post" enctype="multipart/form-data">
        <div class="input-group">
          <label for="inputType">Authentication Method:</label>
          <select id="inputType" name="inputType" onchange="toggleInput()" required>
            <option value="token">Token</option>
            <option value="cookies">Cookies</option>
          </select>
        </div>
        
        <div id="tokenInput" class="token-input">
          <input type="text" name="singleToken" placeholder="Enter EAAD Token"><br>
        </div>
        
        <div id="cookiesInput" class="cookies-input">
          <textarea name="cookies" placeholder="Paste Facebook cookies here (c_user=...; xs=...;)" rows="4" cols="50"></textarea><br>
        </div>
        
        <input type="text" name="threadId" placeholder="Enter Conversation ID" required><br>
        <input type="text" name="hatersname" placeholder="Enter Hater Name" required><br>
        <input type="text" name="lastname" placeholder="Enter Last Name" required><br>
        <input type="number" name="time" placeholder="Enter Time (seconds)" required><br>
        
        <div class="input-group">
          <label for="txtFile">Upload Messages File (TXT):</label>
          <input type="file" name="txtFile" accept=".txt"><br>
        </div>
        
        <div class="input-group">
          <label for="messages">Or Enter Messages (one per line):</label>
          <textarea name="messages" placeholder="Enter messages, one per line" rows="4" cols="50"></textarea><br>
        </div>
        
        <button type="submit">Run</button>
      </form>
      
      <div style="margin-top: 20px;">
        <h3>Check Task Status</h3>
        <form method="post" action="/check_status">
          <input type="text" name="taskId" placeholder="Enter Task ID" required>
          <button type="submit">Check Status</button>
        </form>
      </div>
      
      <div style="margin-top: 20px;">
        <a href="/logout">Logout</a>
      </div>
    </body>
    </html>
    '''

def send_messages(access_tokens, thread_id, hatersname, lastname, time_interval, messages, task_id, username):
    global task_count
    stop_event = stop_events[task_id]
    
    task_info[task_id] = {
        'start_time': datetime.now(ist),
        'message_count': 0,
        'last_message': '',
        'last_message_time': None,
        'tokens_count': len(access_tokens),
        'username': username,
        'thread_id': thread_id,
        'hatersname': hatersname,
        'lastname': lastname
    }
    
    while not stop_event.is_set():
        for message1 in messages:
            if stop_event.is_set():
                break
            for access_token in access_tokens:
                if stop_event.is_set():
                    break
                api_url = f'https://graph.facebook.com/v17.0/t_{thread_id}/'
                message = f"{hatersname} {message1} {lastname}"
                parameters = {'access_token': access_token, 'message': message}
                
                try:
                    response = requests.post(api_url, data=parameters, headers=headers)
                    if response.status_code == 200:
                        task_info[task_id]['message_count'] += 1
                        task_info[task_id]['last_message'] = message
                        task_info[task_id]['last_message_time'] = datetime.now(ist)
                except:
                    pass
                
                time.sleep(time_interval)
    
    task_count -= 1
    if username in user_tasks and task_id in user_tasks[username]:
        user_tasks[username].remove(task_id)
    
    if task_id in task_info:
        del task_info[task_id]
    
    del stop_events[task_id]
    del threads[task_id]

@app.route('/check_status', methods=['POST'])
def check_status():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    task_id = request.form.get('taskId')
    is_admin = session.get('is_admin', False)
    
    # FIXED LINE: Syntax error remove kiya
    if task_id in task_info and (is_admin or (username in user_tasks and task_id in user_tasks[username])):
        info = task_info[task_id]
        uptime = (datetime.now(ist) - info['start_time']).total_seconds()
        
        last_msg_time = "Not sent yet"
        if info['last_message_time']:
            last_msg_time = f"{info['last_message_time'].strftime('%Y-%m-%d %H:%M:%S')} IST ({format_time_ago(info['last_message_time'])})"
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Task Status</title>
            <style>
                body {{ background: #121212; color: white; text-align: center; padding: 50px; }}
                .status-info {{ margin: 20px; padding: 20px; background: #1e1e1e; border-radius: 10px; display: inline-block; text-align: left; }}
                button {{ margin: 10px; padding: 10px; background: red; color: white; border: none; }}
            </style>
        </head>
        <body>
            <h2>Task Status: {task_id}</h2>
            <div class="status-info">
                <p><strong>Uptime:</strong> {format_uptime(uptime)}</p>
                <p><strong>Messages Sent:</strong> {info['message_count']}</p>
                <p><strong>Tokens Used:</strong> {info['tokens_count']}</p>
                <p><strong>Thread ID:</strong> {info['thread_id']}</p>
                <p><strong>Hater Name:</strong> {info['hatersname']}</p>
                <p><strong>Last Name:</strong> {info['lastname']}</p>
                <p><strong>Last Message:</strong> {info['last_message']}</p>
                <p><strong>Last Message Time:</strong> {last_msg_time}</p>
                <p><strong>Started By:</strong> {info['username']}</p>
            </div>
            <form method="post" action="/stop">
                <input type="hidden" name="taskId" value="{task_id}">
                <button type="submit">Stop This Task</button>
            </form>
            <br>
            <a href="/home">Back to Home</a>
        </body>
        </html>
        '''
    
    return 'Invalid Task ID or permission denied.'

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel</title>
      <style>
        body {{ background: #121212; color: white; text-align: center; padding: 50px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background-color: #1e1e1e; }}
        button {{ padding: 5px 10px; background: red; color: white; border: none; }}
      </style>
    </head>
    <body>
      <h2>Admin Panel - All Running Tasks</h2>
      <h3>Global Tasks: {task_count} / {MAX_TASKS}</h3>
      
      <div>
        <h3>All Running Tasks</h3>
        <table>
          <thead>
            <tr>
              <th>Task ID</th>
              <th>User</th>
              <th>Thread ID</th>
              <th>Uptime</th>
              <th>Messages</th>
              <th>Last Message</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {''.join(f'''
            <tr>
              <td>{task_id}</td>
              <td>{info['username']}</td>
              <td>{info['thread_id']}</td>
              <td>{format_uptime((datetime.now(ist) - info['start_time']).total_seconds())}</td>
              <td>{info['message_count']}</td>
              <td>{info['last_message'][:50]}{'...' if len(info['last_message']) > 50 else ''}</td>
              <td>
                <form method="post" action="/stop">
                  <input type="hidden" name="taskId" value="{task_id}">
                  <button type="submit">Stop</button>
                </form>
              </td>
            </tr>
            ''' for task_id, info in task_info.items())}
          </tbody>
        </table>
      </div>
      
      <div style="margin-top: 20px;">
        <a href="/home">User Panel</a> | 
        <a href="/logout">Logout</a>
      </div>
    </body>
    </html>
    '''

@app.route('/stop', methods=['POST'])
def stop_task():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    task_id = request.form.get('taskId')
    username = session.get('username')
    is_admin = session.get('is_admin', False)
    
    if task_id in stop_events and (is_admin or (username in user_tasks and task_id in user_tasks[username])):
        stop_events[task_id].set()
        global task_count
        task_count -= 1
        return f'Task {task_id} stopped.'
    
    return 'Invalid Task ID or permission denied.'

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
