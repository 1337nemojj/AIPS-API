from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import threading
import time
import json
import os
import subprocess
import requests
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'red_team_ai_agent_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Глобальные переменные для хранения состояния
pentest_status = {
    "status": "idle",  # idle, running, paused, completed, error
    "current_phase": None,
    "current_step": None,
    "target": None,
    "start_time": None,
    "vulnerabilities": [],
    "logs": []
}

# Конфигурация Metasploit RPC
msfrpc_config = {
    "host": "192.168.31.44",
    "port": 55553,
    "username": "msf",
    "password": "password",
    "ssl": False
}

# Конфигурация LLM
llm_config = {
    "endpoint": "https://openrouter.ai/api/v1/chat/completions",
    "model": "deepseek/deepseek-r1-0528-qwen3-8b:free",
    "max_tokens": 1000,
    "temperature": 0.2,
    "api_key": "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"  # Uncomment and set if you have an API key
}

# Этапы пентеста
PENTEST_PHASES = [
    "reconnaissance",
    "vulnerability_scanning",
    "vulnerability_analysis",
    "exploitation",
    "post_exploitation",
    "reporting"
]

# Функция для запуска Metasploit RPC сервера
def start_msfrpc():
    try:
        # Проверяем, запущен ли уже msfrpcd
        ps_process = subprocess.run(["ps", "-ef"], capture_output=True, text=True)
        if "msfrpcd" in ps_process.stdout:
            logger.info("Metasploit RPC server is already running")
            return True
        
        # Запускаем msfrpcd
        cmd = [
            "msfrpcd",
            "-U", msfrpc_config["username"],
            "-P", msfrpc_config["password"],
            "-a", msfrpc_config["host"],
            "-p", str(msfrpc_config["port"]),
            "-S" if msfrpc_config["ssl"] else ""
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)  # Даем время на запуск
        
        # Проверяем, запустился ли сервер
        if process.poll() is None:
            logger.info("Metasploit RPC server started successfully")
            return True
        else:
            stdout, stderr = process.communicate()
            logger.error(f"Failed to start Metasploit RPC server: {stderr.decode()}")
            return False
    except Exception as e:
        logger.error(f"Error starting Metasploit RPC server: {str(e)}")
        return False

# Класс для взаимодействия с Metasploit через RPC
class MetasploitRPC:
    def __init__(self, host, port, username, password, ssl=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.token = None
        self.base_url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"
        
    def login(self):
        try:
            response = requests.post(
                self.base_url + "auth/login",
                json={"username": self.username, "password": self.password}
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                logger.info("Successfully logged in to Metasploit RPC")
                return True
            else:
                logger.error(f"Failed to login to Metasploit RPC: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error logging in to Metasploit RPC: {str(e)}")
            return False
    
    def execute_command(self, command):
        if not self.token:
            if not self.login():
                return {"success": False, "error": "Not authenticated"}
        
        try:
            # Разбиваем команду на части
            parts = command.strip().split()
            
            if not parts:
                return {"success": False, "error": "Empty command"}
            
            # Обрабатываем различные типы команд
            if parts[0] == "use":
                return self._execute_use_command(parts[1])
            elif parts[0] == "set":
                return self._execute_set_command(parts[1], " ".join(parts[2:]))
            elif parts[0] == "run" or parts[0] == "exploit":
                return self._execute_run_command()
            elif parts[0] == "search":
                return self._execute_search_command(" ".join(parts[1:]))
            else:
                # Общая команда консоли
                return self._execute_console_command(command)
        except Exception as e:
            logger.error(f"Error executing Metasploit command: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _execute_use_command(self, module_path):
        try:
            response = requests.post(
                self.base_url + "modules/use",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"module_type": module_path.split("/")[0], "module_name": "/".join(module_path.split("/")[1:])}
            )
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _execute_set_command(self, option, value):
        try:
            response = requests.post(
                self.base_url + "modules/options/set",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"option": option, "value": value}
            )
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _execute_run_command(self):
        try:
            response = requests.post(
                self.base_url + "modules/execute",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _execute_search_command(self, query):
        try:
            response = requests.get(
                self.base_url + f"modules/search?query={query}",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _execute_console_command(self, command):
        try:
            response = requests.post(
                self.base_url + "console/write",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"command": command + "\n"}
            )
            if response.status_code == 200:
                # Ждем результат
                time.sleep(1)
                read_response = requests.get(
                    self.base_url + "console/read",
                    headers={"Authorization": f"Bearer {self.token}"}
                )
                if read_response.status_code == 200:
                    data = read_response.json()
                    return {"success": True, "data": data}
                else:
                    return {"success": False, "error": read_response.text}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

# Класс для взаимодействия с LLM
class LLMController:
    def __init__(self, endpoint, model, max_tokens=1000, temperature=0.2, api_key=None):
        self.endpoint = endpoint
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.api_key = api_key

    def generate_command(self, context):
        try:
            with open("prompts/llm_agent_prompt.md", "r",  encoding="utf-8") as f:
                prompt = f.read()
            # OpenRouter expects a list of messages
            messages = [
                {
                    "role": "system",
                    "content": prompt
                },
                {
                    "role": "user",
                    "content": json.dumps(context)
                }
            ]
            headers = {
                "Content-Type": "application/json"
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = requests.post(
                url=self.endpoint,
                headers=headers,
                data=json.dumps({
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature
                })
            )
            if response.status_code == 200:
                data = response.json()
                # OpenRouter returns choices[0]['message']['content']
                command_text = self._extract_command(data["choices"][0]["message"]["content"])
                return {"success": True, "command": command_text}
            else:
                logger.error(f"Failed to generate command: {response.text}")
                return {"success": False, "error": response.text}
        except Exception as e:
            logger.error(f"Error generating command: {str(e)}")
            return {"success": False, "error": str(e)}

    def analyze_result(self, command, result, context):
        try:
            with open("prompts/llm_agent_prompt.md", "r", encoding="utf-8") as f:
                prompt = f.read()
            analysis_prompt = f"{prompt}\n\nCOMMAND: {command}\n\nRESULT: {result}\n\nCONTEXT: {json.dumps(context)}\n\nPlease analyze the result and provide your analysis."
            messages = [
                {
                    "role": "system",
                    "content": prompt
                },
                {
                    "role": "user",
                    "content": analysis_prompt
                }
            ]
            headers = {
                "Content-Type": "application/json"
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = requests.post(
                url=self.endpoint,
                headers=headers,
                data=json.dumps({
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature
                })
            )
            if response.status_code == 200:
                data = response.json()
                analysis = self._extract_analysis(data["choices"][0]["message"]["content"])
                return {"success": True, "analysis": analysis}
            else:
                logger.error(f"Failed to analyze result: {response.text}")
                return {"success": False, "error": response.text}
        except Exception as e:
            logger.error(f"Error analyzing result: {str(e)}")
            return {"success": False, "error": str(e)}

    def _extract_command(self, text):
        if "COMMAND:" in text:
            command_section = text.split("COMMAND:")[1].split("EXPLANATION:")[0].strip()
            return command_section
        return None

    def _extract_analysis(self, text):
        if "ANALYSIS:" in text:
            analysis_section = text.split("ANALYSIS:")[1].strip()
            return analysis_section
        return None

# Класс для управления процессом пентестинга
class PentestOrchestrator:
    def __init__(self, metasploit_rpc, llm_controller):
        self.metasploit_rpc = metasploit_rpc
        self.llm_controller = llm_controller
        self.context = {
            "phase": "reconnaissance",
            "step": 0,
            "target": None,
            "discovered_info": {},
            "vulnerabilities": []
        }
        self.running = False
        self.thread = None
    
    def start_pentest(self, target):
        global pentest_status
        if self.running:
            return {"success": False, "error": "Pentest already running"}
        
        self.context["target"] = target
        self.context["phase"] = PENTEST_PHASES[0]
        self.context["step"] = 0
        self.context["discovered_info"] = {}
        self.context["vulnerabilities"] = []
        
        # Обновляем глобальное состояние
        pentest_status["status"] = "running"
        pentest_status["current_phase"] = PENTEST_PHASES[0]
        pentest_status["current_step"] = 0
        pentest_status["target"] = target
        pentest_status["start_time"] = time.time()
        pentest_status["vulnerabilities"] = []
        pentest_status["logs"] = []
        
        # Запускаем пентест в отдельном потоке
        self.running = True
        self.thread = threading.Thread(target=self._run_pentest)
        self.thread.daemon = True
        self.thread.start()
        
        return {"success": True, "message": f"Started pentest against {target}"}
    
    def stop_pentest(self):
        if not self.running:
            return {"success": False, "error": "No pentest running"}
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        
        # Обновляем глобальное состояние
        global pentest_status
        pentest_status["status"] = "completed" if pentest_status["current_phase"] == PENTEST_PHASES[-1] else "stopped"
        
        return {"success": True, "message": "Pentest stopped"}
    
    def pause_pentest(self):
        if not self.running:
            return {"success": False, "error": "No pentest running"}
        
        self.running = False
        
        # Обновляем глобальное состояние
        global pentest_status
        pentest_status["status"] = "paused"
        
        return {"success": True, "message": "Pentest paused"}
    
    def resume_pentest(self):
        global pentest_status
        if self.running:
            return {"success": False, "error": "Pentest already running"}
        
        if pentest_status["status"] != "paused":
            return {"success": False, "error": "No paused pentest to resume"}
        
        # Обновляем глобальное состояние
        pentest_status["status"] = "running"
        
        # Запускаем пентест в отдельном потоке
        self.running = True
        self.thread = threading.Thread(target=self._run_pentest)
        self.thread.daemon = True
        self.thread.start()
        
        return {"success": True, "message": "Pentest resumed"}
    
    def _run_pentest(self):
        try:
            while self.running:
                # Генерируем команду на основе текущего контекста
                command_result = self.llm_controller.generate_command(self.context)
                
                if not command_result["success"]:
                    self._log_error(f"Failed to generate command: {command_result.get('error', 'Unknown error')}")
                    time.sleep(5)
                    continue
                
                command = command_result["command"]
                if not command:
                    self._log_error("Generated empty command")
                    time.sleep(5)
                    continue
                
                # Логируем команду
                self._log_command(command)
                
                # Выполняем команду
                result = self.metasploit_rpc.execute_command(command)
                
                if not result["success"]:
                    self._log_error(f"Command execution failed: {result.get('error', 'Unknown error')}")
                    time.sleep(5)
                    continue
                
                # Логируем результат
                result_text = json.dumps(result["data"]) if "data" in result else "No data returned"
                self._log_result(result_text)
                
                # Анализируем результат
                analysis_result = self.llm_controller.analyze_result(command, result_text, self.context)
                
                if not analysis_result["success"]:
                    self._log_error(f"Failed to analyze result: {analysis_result.get('error', 'Unknown error')}")
                    time.sleep(5)
                    continue
                
                analysis = analysis_result["analysis"]
                if not analysis:
                    self._log_error("Generated empty analysis")
                    time.sleep(5)
                    continue
                
                # Логируем анализ
                self._log_analysis(analysis)
                
                # Обновляем контекст на основе анализа
                self._update_context(analysis)
                
                # Проверяем, нужно ли перейти к следующему этапу
                self._check_phase_transition()
                
                # Проверяем, завершен ли пентест
                if self.context["phase"] == PENTEST_PHASES[-1] and self._is_phase_completed():
                    self._log_info("Pentest completed")
                    global pentest_status
                    pentest_status["status"] = "completed"
                    self.running = False
                    break
                
                # Пауза между командами
                time.sleep(2)
        except Exception as e:
            #global pentest_status
            logger.error(f"Error in pentest thread: {str(e)}")
            pentest_status["status"] = "error"
            self.running = False
    
    def _log_command(self, command):
        log_entry = {
            "type": "command",
            "content": command,
            "timestamp": time.time()
        }
        global pentest_status
        pentest_status["logs"].append(log_entry)
        socketio.emit("log_update", log_entry)
        logger.info(f"Command: {command}")
    
    def _log_result(self, result):
        log_entry = {
            "type": "result",
            "content": result,
            "timestamp": time.time()
        }
        global pentest_status
        pentest_status["logs"].append(log_entry)
        socketio.emit("log_update", log_entry)
        logger.info(f"Result: {result[:100]}...")
    
    def _log_analysis(self, analysis):
        log_entry = {
            "type": "analysis",
            "content": analysis,
            "timestamp": time.time()
        }
        global pentest_status
        pentest_status["logs"].append(log_entry)
        socketio.emit("log_update", log_entry)
        logger.info(f"Analysis: {analysis[:100]}...")
    
    def _log_info(self, message):
        log_entry = {
            "type": "info",
            "content": message,
            "timestamp": time.time()
        }
        global pentest_status
        pentest_status["logs"].append(log_entry)
        socketio.emit("log_update", log_entry)
        logger.info(message)
    
    def _log_error(self, message):
        log_entry = {
            "type": "error",
            "content": message,
            "timestamp": time.time()
        }
        global pentest_status
        pentest_status["logs"].append(log_entry)
        socketio.emit("log_update", log_entry)
        logger.error(message)
    
    def _update_context(self, analysis):
        global pentest_status
        # Обновляем контекст на основе анализа
        # Это упрощенная реализация, в реальном приложении нужно парсить анализ
        if "VULNERABILITIES:" in analysis:
            vulns_section = analysis.split("VULNERABILITIES:")[1].split("NEXT_STEPS:")[0].strip()
            vulns = [v.strip() for v in vulns_section.split("-") if v.strip()]
            for vuln in vulns:
                if vuln not in self.context["vulnerabilities"]:
                    self.context["vulnerabilities"].append(vuln)
                    # Добавляем уязвимость в глобальное состояние
                    global pentest_status
                    pentest_status["vulnerabilities"].append({
                        "name": vuln,
                        "phase": self.context["phase"],
                        "timestamp": time.time()
                    })
                    socketio.emit("vulnerability_found", {
                        "name": vuln,
                        "phase": self.context["phase"],
                        "timestamp": time.time()
                    })
        
        # Увеличиваем счетчик шагов
        self.context["step"] += 1
        pentest_status["current_step"] = self.context["step"]
        socketio.emit("status_update", {
            "status": pentest_status["status"],
            "current_phase": pentest_status["current_phase"],
            "current_step": pentest_status["current_step"]
        })
    
    def _check_phase_transition(self):
        # Проверяем, нужно ли перейти к следующему этапу
        # Это упрощенная реализация, в реальном приложении нужна более сложная логика
        if self._is_phase_completed():
            current_phase_index = PENTEST_PHASES.index(self.context["phase"])
            if current_phase_index < len(PENTEST_PHASES) - 1:
                next_phase = PENTEST_PHASES[current_phase_index + 1]
                self.context["phase"] = next_phase
                self.context["step"] = 0
                global pentest_status
                pentest_status["current_phase"] = next_phase
                pentest_status["current_step"] = 0
                socketio.emit("phase_change", {
                    "previous_phase": PENTEST_PHASES[current_phase_index],
                    "new_phase": next_phase
                })
                self._log_info(f"Moving to next phase: {next_phase}")
    
    def _is_phase_completed(self):
        # Определяем, завершен ли текущий этап
        # Это упрощенная реализация, в реальном приложении нужна более сложная логика
        phase_steps = {
            "reconnaissance": 10,
            "vulnerability_scanning": 15,
            "vulnerability_analysis": 10,
            "exploitation": 10,
            "post_exploitation": 10,
            "reporting": 5
        }
        return self.context["step"] >= phase_steps.get(self.context["phase"], 10)

# Инициализация компонентов
metasploit_rpc = None
llm_controller = None
pentest_orchestrator = None

# Маршруты API
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify(pentest_status)

@app.route('/api/pentest/start', methods=['POST'])
def start_pentest():
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({"success": False, "error": "Target is required"}), 400
    
    result = pentest_orchestrator.start_pentest(target)
    return jsonify(result)

@app.route('/api/pentest/stop', methods=['POST'])
def stop_pentest():
    result = pentest_orchestrator.stop_pentest()
    return jsonify(result)

@app.route('/api/pentest/pause', methods=['POST'])
def pause_pentest():
    result = pentest_orchestrator.pause_pentest()
    return jsonify(result)

@app.route('/api/pentest/resume', methods=['POST'])
def resume_pentest():
    result = pentest_orchestrator.resume_pentest()
    return jsonify(result)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    return jsonify(pentest_status["logs"])

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    return jsonify(pentest_status["vulnerabilities"])

# События WebSocket
@socketio.on('connect')
def handle_connect():
    emit('status_update', {
        "status": pentest_status["status"],
        "current_phase": pentest_status["current_phase"],
        "current_step": pentest_status["current_step"]
    })

# Инициализация приложения
def init_app():
    global metasploit_rpc, llm_controller, pentest_orchestrator
    
    # Запускаем Metasploit RPC сервер
    # if not start_msfrpc():
    #     logger.error("Failed to start Metasploit RPC server")
    #     return False
    
    # Инициализируем компоненты
    metasploit_rpc = MetasploitRPC(
        msfrpc_config["host"],
        msfrpc_config["port"],
        msfrpc_config["username"],
        msfrpc_config["password"],
        msfrpc_config["ssl"]
    )
    
    llm_controller = LLMController(
        llm_config["endpoint"],
        llm_config["model"],
        llm_config["max_tokens"],
        llm_config["temperature"],
        llm_config.get("api_key")  # Pass API key if present
    )
    
    pentest_orchestrator = PentestOrchestrator(metasploit_rpc, llm_controller)
    
    return True

if __name__ == '__main__':
    if init_app():
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        logger.error("Failed to initialize application")
