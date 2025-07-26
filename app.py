#app.py
#Author: Scott Stage
#Created: 12/31/2024

from flask import Flask, Response, jsonify, make_response, render_template, request, stream_with_context
                                   #https://flask.palletsprojects.com/en/stable/
import os                          #https://github.com/python/cpython/blob/3.13/Lib/os.py
import threading                   #https://github.com/python/cpython/blob/3.13/Lib/threading.py
import datetime                    #https://github.com/python/cpython/blob/3.13/Lib/datetime.py
import socket                      #https://github.com/python/cpython/blob/3.13/Lib/socket.py
import json                        #https://github.com/python/cpython/blob/3.13/Lib/json/__init__.py
import time                        #https://github.com/python/cpython/blob/main/Doc/library/time.rst
import traceback                   #https://github.com/python/cpython/blob/3.13/Lib/traceback.py
import atexit                      #https://github.com/python/cpython/blob/main/Doc/library/atexit.rst
import queue                       #https://github.com/python/cpython/blob/3.13/Lib/queue.py
import yaml                        #https://yaml.org/
import requests
import certstream

app = Flask(__name__)

def load_config_yaml(file_path):
  with open(file_path, 'r') as f:
      config = yaml.safe_load(f)
  return config


config = load_config_yaml("config.yaml")
dateFormatPython = config["dateFormatPython"]
hostname = config["hostname"]
port = config["port"]
logFile = config["logFile"]
delimiter = config["delimiter"]

sse_queue = queue.Queue() # Create a new Queue to pass data to sse.
command_queue = queue.Queue()      

          
def log_write(log_message):
    timestamp = datetime.datetime.now().strftime(dateFormatPython)
    log_line = f"{timestamp} -       app.py: {log_message}\n"
    try:
        with open(logFile, "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Error writing to log file {logFile}: {e}")



class SocketClient:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = None
        self.connect()
        self.keep_alive_interval = 300 # Send keep alive every 300 seconds / 5 minutes
        self.auto_refresh_interval = -1
        self.threads = []
        self.create_threads()

    def connect(self):
      try:
          log_write(f"Attempting to connect to SocTools at: {self.hostname}:{self.port}")
          self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.socket.connect((self.hostname, self.port))
          local_address = self.socket.getsockname()
          ip, port = local_address
          log_write(f"Connected Established!")
          log_write(f"app.py({ip}:{port}) <---> SocTools.ps1({self.hostname}:{self.port})")
      except Exception as e:
        log_write(f"Error connecting to socket: {e}\n {traceback.format_exc()}")


    def is_socket_connected(self):
        if self.socket is None or self.socket.fileno() == -1:
            return false
        try:
            self.socket.getsockname()
            return True
        except socket.error:
            return False


    def send_command(self, command):
        try:
            if not self.is_socket_connected():
                log_write("Reconnecting due to closed socket.")
                self.connect()
            if not self.is_socket_connected(): # verify that connect worked
                log_write("Error reconnecting to socket, returning None.")
                return None
    
            self.socket.sendall((command + '\n').encode('utf-8'))
            data = b""
            start_time = time.time()
            while True:
                try:
                    self.socket.settimeout(10) # sets timeout to 10 seconds
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        log_write("No data received in 10 seconds, breaking.")
                        break
                    data += chunk
                    if delimiter.encode('utf-8') in data:
                        break
                except socket.timeout:
                    log_write("Socket timed out during recv, breaking.")
                    break
                except socket.error as se:
                    log_write(f"Socket error during recv, closing socket and breaking: {se}\n {traceback.format_exc()}")
                    self.socket.close()
                    self.socket = None
                    break
                if time.time() - start_time > 20: # add timeout for the recv loop.
                    log_write("Receive loop timed out after 20 seconds, breaking.")
                    break
    
            data_str = data.decode('utf-8', 'ignore') # Decode all of the data
            
            if delimiter in data_str: # Verify delimiter is present
                data_str = data_str.split(delimiter)[0] # Split before cleaning
                data_str = data_str.strip()
                result = json.loads(data_str)  # Attempt to parse
                return result
            else:
                log_write(f"Error: Delimiter not found in data. Returning None.")
                return None
    
    
        except json.JSONDecodeError as json_err:
            log_write(f"Error parsing json: {json_err}\nData: {data_str} {traceback.format_exc()}") # Get detailed error
            return None
        except Exception as e:
            log_write(f"Error sending command to powershell: {e}\n {traceback.format_exc()}")
        return None

    def close(self):
        if self.socket:
            log_write(f"Closing connection to {self.hostname}:{self.port}")
            self.socket.close()
        else:
            log_write("Socket already closed.")
            
    


    def powershell_thread_handler(self):
        while True:
            try:  
                command = command_queue.get(timeout = 10)
                log_write(f"Gather command from command_queue : {command}")
                   
                results = self.send_command(command)
                
                log_write(f"Results from powershell_thread_handler -> send_command : {results}")
                sse_queue.put(results)
                
                command_queue.task_done()
            except queue.Empty:
                log_write(f"Queue empty")
                continue

            
    #------------------------------      

    def set_refresh_interval(self, value):
        self.auto_refresh_interval = value
        log_write(f"Auto Refresh interval changed to : {self.auto_refresh_interval}")

    def _auto_refresh(self):
        while True:
            if(int(self.auto_refresh_interval) != -1):
                time.sleep(int(self.auto_refresh_interval))
                try:
                    log_write(f"Sending threaded GetCurrentUserInfo")
                    command_queue.put(json.dumps({"action": "GetCurrentUserInfo"}))
                    
                except Exception as e:
                    log_write(f"Error sending keep alive: {e}\n {traceback.format_exc()}")
                    
    
    #-----------------------------
    
    def _exo_status_update(self):
        while True:
            time.sleep(60)
            try:
                log_write(f"Sending threaded CheckExoConnection")
                command_queue.put(json.dumps({"action": "CheckExoConnection"}))                
            except Exception as e:
                log_write(f"Error sending keep alive: {e}\n {traceback.format_exc()}")
                
        
    #-----------------------------


    def _send_keep_alive(self):
        while True:
            time.sleep(self.keep_alive_interval)
            try:
                log_write(f"Sending threaded keepalive")
                command_queue.put(json.dumps({"action": "keepalive"}))
            except Exception as e:
                log_write(f"Error sending keep alive: {e}\n {traceback.format_exc()}")
     

    def create_threads(self):
        powershell_thread = threading.Thread(target=self.powershell_thread_handler, daemon=True)
        keep_alive_thread = threading.Thread(target=self._send_keep_alive, daemon=True)
        exo_status_update_thread = threading.Thread(target=self._exo_status_update, daemon=True)
        auto_refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        
        self.threads.append(powershell_thread)
        self.threads.append(auto_refresh_thread)
        self.threads.append(exo_status_update_thread)
        self.threads.append(keep_alive_thread)
        
        powershell_thread.start()
        auto_refresh_thread.start()
        keep_alive_thread.start()
        exo_status_update_thread.start()
        
        #for thread in self.threads:
        #    thread.join()
    



# Instantiate the socket client at app startup
socket_client = SocketClient(hostname, port)

@app.route('/')
def index():
    # Get the current time
    current_timestamp = time.time()
    # Prepare the response and cache control headers
    response = make_response(render_template("index.html", current_time=current_timestamp))
    # Set cache control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/logs')
def get_text_content():
    return render_template("logs.html")

@app.route('/harddelete')
def hard_delete():
    return render_template('exoutils/harddelete.html')


@app.route('/omeportal')
def ome_portal():
    return render_template('exoutils/omeportal.html')


@app.route('/revokemessage')
def revoke_message():
    return render_template('exoutils/revokemessage.html')
    

@app.route('/events', methods=['POST'])
def events():
    if request.method == 'POST':
        command = request.get_json()
        if command and command.get("action"):
            if(command.get("action") == "changeRefreshInterval"):
                socket_client.set_refresh_interval(json.dumps(command.get("input")))
            else:
                log_write(f"Sending Command to command_queue: {command}")
                command_queue.put(json.dumps(command))
            return { "": "204"}
        else:
            return { "error": "command not found"}
            

@app.route('/sse')
def sse():
    def event_stream():
        while True:
            try:
                message = sse_queue.get(timeout=0.2)  # Add a timeout
                log_write(f"Yielding message from /sse: {message}")
                yield f"data: {json.dumps(message)}\n\n"
            except queue.Empty:
                log_write("Queue empty")  # Optional: log if desired, but not necessary
                yield f"data: {json.dumps({"action": "SSE Queue Empty"})}\n\n"
                continue
            except Exception as e:
                 log_write(f"Error in sse stream: {e}\n {traceback.format_exc()}") # Log any errors
                 break # Break out of the loop if there are other issues.
    
    return Response(event_stream(), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache'})

        

def generate_log_events():
    logFile = "logs/SocTools.log"
    last_modified_time = os.path.getmtime(logFile)
    try:
        with open(logFile, 'r') as f:
            text_content = f.read()
            yield f"data: {json.dumps({'content': text_content})}\n\n"
    except FileNotFoundError:
        yield f"data: {json.dumps({'content': 'File Not Found'})}\n\n"

    while True:
        time.sleep(1)  # Check every second
        current_modified_time = os.path.getmtime(logFile)
        if current_modified_time != last_modified_time:
            last_modified_time = current_modified_time
            try:
                with open(logFile, 'r') as f:
                    text_content = f.read()
                    yield f"data: {json.dumps({'content': text_content})}\n\n"
            except FileNotFoundError:
                    yield f"data: {json.dumps({'content': 'File Not Found'})}\n\n"

@app.route('/log-stream')
def log_stream():
    return Response(generate_log_events(), mimetype='text/event-stream')

def close_socket_connection():
    socket_client.close()

# close the socket when the app shuts down.
atexit.register(close_socket_connection)


if __name__ == '__main__':       
    app.run(debug=True, threaded = True, use_reloader=False)