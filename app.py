#importazione di librerie 
from email import errors 
from flask import Flask,request,render_template,redirect,url_for,flash,session
from werkzeug.security import generate_password_hash,check_password_hash 
import re
from validate_email_address import validate_email 
import mysql.connector 
from flask import Flask, abort, request, render_template, jsonify
import requests
import json
from collections import defaultdict
import time
import logging
from logging.handlers import RotatingFileHandler
from flask_socketio import SocketIO
from prometheus_client import generate_latest
from datetime import datetime






# Inizializza l'app Flask   
app=Flask(__name__) #definiamo la variabile che è un istanza di flask dove name è semplicmemte il nome del file è cosi di standard non si cambia
socketio = SocketIO(app)

#Variabile globale per memorizzare l'URL del server di destinazione
serverDestinazione = "http://localhost:5000" # valore inizialmente di default

db=mysql.connector.connect(
       host="localhost",
       user="root",
       password="",
       database="pysql"
    )

@app.route('/', methods=['GET']) 
def Home(): 
    return render_template('Home.html')
    
@app.route('/Accedi',methods=['GET','POST']) 
def Accedi(): 
    if request.method=='POST': 
       name=request.form.get('name')
       password=request.form.get('password') 

       cursor=db.cursor()
       query="SELECT * FROM accessii WHERE Utente=%s && Password=%s"
       cursor.execute(query,(name,password))
       user=cursor.fetchone()
       cursor.close
       
       if user:
            return redirect(url_for('areaUser')) 
    return render_template('Accedi.html')#serve per farvi ritornare la pagina html per l'accesso se il metodo invece è get

@app.route('/areaUser',methods=['GET','POST'])
def areaUser():
    return render_template('areaUser.html') 

file_regole = 'waf_rules.json'

def carico_waf_rules():
    try:
        with open('waf_rules.json', 'r') as f:
            return json.load(f) #Carica il file JSON e restituisce le regole
    except FileNotFoundError:
        #Se il file non è trovato, ritorna un set di regole predefinite
        {
    "sql_patterns": [
        r"(?i)\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC)\b",
        r"(?i)\b(OR|AND)\b|[0-1]"
    ],
    "xss_patterns": [
        r"(?i)<script.*?>.*?</script>",
        r"(?i)javascript:",
        r"(?i)on\w*=",
        r"(?i)eval\(",
        r"(?i)expression\(",
        r"(?i)alert\(",
        r"(?i)document\.location",
        r"(?i)window\.location"
    ]
}
    
#Carica le regole iniziali
regole_waf = carico_waf_rules()

def salva_waf_rules(regole):
    with open('waf_rules.json', 'w') as f:
        json.dump(regole_waf, f, indent=4) 

def salva_richiesta_malevola(metodo, url, parametri, risultato, timestamp, utente_id):
    cursor = db.cursor()

    query = """
        INSERT INTO richieste (metodo, url, parametri, risultati, timestamp, utente_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(query, (metodo, url, str(parametri), risultato, timestamp, utente_id))
    db.commit()
    cursor.close()


#Funzione per rilevare SQL Injection 
def sql_injection(value, metodo, url, parametri, utente_id): #value stringa da controllare
    for regola in regole_waf:
        if regola["enabled"]:
            if regola["nome"] == "Protezione contro SQL Injection":
                for pattern in regola["regex"]:
                    if re.search(pattern, value): 
                        sql_error = "SQL Injection rilevata"
                        print(f"SQL Injection detected: {value}") #vedrò questo messaggio nel server perchè il server in modalità debug
                        salva_richiesta_malevola(metodo,url,parametri,sql_error,datetime.now(), utente_id)
                        return sql_error
    return None #Se non c'è SQL Injection


#Funzione per rilevare XSS
def xss_attack(value, metodo, url, parametri, utente_id):
    for regola in regole_waf:
        if regola["enabled"]:
            if regola["nome"] == "Protezione contro Cross-Site Scripting(XSS)":
                for pattern in regola["regex"]:
                    if re.search(pattern, value):
                        xss_error = "XSS rilevata"
                        print(f"XSS detected: {value}")
                        salva_richiesta_malevola(metodo,url,parametri,xss_error,datetime.now(), utente_id)
                        return xss_error

    return None #Se non c'è SQL Injection

#Funzione per sanificare l'input
def sanitize_input(value, metodo, url, parametri, utente_id):
    sql_error = sql_injection(value,metodo,url,parametri,utente_id) #mi salva qui il ritorno della funzione sql_injection
    if sql_error: #true se contiene un valore(qualsiasi cosa che non è none quindi)
        return render_template('errorPage.html',error_message = sql_error), 400 #Risposta con codice 400
    
    xss_error = xss_attack(value, metodo, url,parametri,utente_id)
    if xss_error:
        return render_template('errorPage.html',error_message = xss_error), 400
    
    #Se non ci sono errori, restituisce il valore
    return value 
            
#Route per ricevere le richieste dal client
@app.route('/<path:path>', methods= ['GET','POST',])
#Funzione che prende in input le richieste per poterle filtrare
def proxyinverso(path):
    url = f"{serverDestinazione}/{path}"

    headers = {key: value for key, value in request.headers if key != 'Host'}

    utente_id = 1

    if request.method == 'GET':
        params = request.args #parametri della query string
        print(f"GET request to:{url}")
        print(f"Parameters:{params}")

        for key, value in params.items():
            sanitized_value = sanitize_input(value,request.method,url,params, utente_id) #sanifica ogni parametr
            if isinstance(sanitized_value,tuple): #se la sanificazione ha trovato un errore
               return sanitized_value #ritorna l'errore senza inviare la richiesta al server

        #Solo se tutti i parametri sono validi, invio la richiesta al server 
        try:
            response = requests.get(url,params=params,headers=headers)
            #corpo della risposta, codice di stato HTTP,intestazioni HTTP
            return(response.content,response.status_code,response.headers.items())
       #RequestsException è una classe base per le eccezioni per errori relativi
       #a timeout connessione, errore di rete, DNS errori
        except requests.exceptions.RequestException:
            abort(500,description="Errore nella richiesta GET al server di destinazione")

    elif request.method == 'POST':
        data = request.get_data() #metodo che mi cattura i dati raw che il client vuole inviare al server (modulo HTML, dati JSON)
        print(f"POST request to:{url}") #Stampo l'url cui la richiesta post e indirizzata
        print(f"Data:{data.decode('utf-8')}")
        
        sanitized_data = sanitize_input(data.decode('utf-8'), request.method, url, None, utente_id) #sanifica i dati POST
        if isinstance(sanitized_data,tuple): #Se è un errore
            return sanitized_data #ritorna l'errore e blocca la richiesta

        try:
            response = requests.post(url, data=data,headers=headers)
            return (response.content, response.status_code, response.headers.items())
        except requests.exceptions.RequestException:
                abort(500, description="Errore nella richiesta POST al server di destinazione")


@app.route('/favicon.ico')
def favicon():
    return '', 204  # Risposta vuota con codice di stato 204 (No Content)

# configurazione WAF
@app.route('/Configurazione',methods=['GET','POST'])
def Configurazione():
    if request.method=='POST':
        name=request.args.get('name') 
        password=request.args.get('password')
    return render_template("Configurazione.html",file_regola=regole_waf)

# Rotta per aggiungere una regola
@app.route('/aggiungi_regola', methods=['GET', 'POST'])
def aggiungi_regola():
    if request.method == 'POST':
        id=request.form.get('id')
        nome = request.form.get('nome')
        regex = request.form.get('regex')
        nuova_regola = {"id":f"regola{len(regole_waf) + 1}", "nome": nome, "enabled": False, "regex": [regex]}
        salva_waf_rules(regole_waf.append(nuova_regola) ) 
        return jsonify({"message": "Regola aggiunta con successo!"}), 201
    return render_template('Configurazione.html')


# Rotta per modificare una regola
@app.route('/modifica_regola', methods=['GET', 'POST'])
def modifica_regola():
    if request.method == 'POST':
        regola_id = request.form.get('id')
        nuova_regex = request.form.get('regex')
        for regola in regole_waf:
            if regola["id"] == regola_id:
                regola["regex"] = [nuova_regex]
                salva_waf_rules(regole_waf)
                return jsonify({"message": "Regola modificata con successo!"}), 200
        return jsonify({"error": "Regola non trovata!"}), 404
    return render_template('Configurazione.html')

# Rotta per rimuovere una regola
@app.route('/rimuovi_regola', methods=['GET', 'POST'])
def rimuovi_regola():
    if request.method == 'POST':
        regola_id = request.form.get('id') 
        global regole_waf
        regole_waf = [regola for regola in regole_waf if regola["id"] != regola_id]
        salva_waf_rules(regole_waf)
        return jsonify({"message": "Regola rimossa con successo!"}), 200
    return render_template('Configurazione.html') 

@app.route('/Report', methods=['GET','POST'])
def Report(): 
    utente_id = 1
    cursor = db.cursor()
    query = "SELECT * FROM richieste WHERE utente_id = %s AND timestamp >= CURDATE() - INTERVAL 1 MONTH "
    cursor.execute(query, (utente_id,))
    richieste= cursor.fetchall()  # Ottieni tutte le richieste dell'utente
    cursor.close()
    return render_template('Report.html', richieste = richieste)

@app.route('/Monitoraggio', methods=['GET', 'POST'])
def Monitoraggio():
    #Mostra la pagina principale con il grafico.
    return render_template('Monitoraggio.html')

# Configurazione logging
handler = RotatingFileHandler("waf.log", maxBytes=5000000, backupCount=5) # Salva i log in file con una dimensione massima di 5MB e conserva 5 file di backup.
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", handlers=[handler])


# Dalla riga 20 alla riga 31 ho inserito una lista nera di prova e ho inserito anche come prova il rate limit
# Lista nera per pattern malevoli XSS e SQL Injection
LISTA_NERA_REGEX = [
    r"<script.*?>.*?</script.*?>",
    r"(?i)DROP TABLE",
    r"(?i)UNION SELECT",
    r"--",
    r";"
]

# Rate limiting
RATE_LIMIT = 15
RATE_PERIOD = 1   # Ogni IP può fare al massimo 4 richieste in 2 secondi
rate_limit_data = defaultdict(list)


"""
Inizializzazione valori statistiche 
Variabili per tenere traccia del numero totale di richieste, richieste bloccate e malevole, e violazioni del rate-limit.
"""
stats = {
    "total_requests": 0,
    "malicious_requests": 0,
    "blocked_requests": 0,
    "rate_limit": 0,
}

# Verifica se il payload corrisponde a uno dei pattern della lista nera
def is_malicious(payload):
   
    for pattern in LISTA_NERA_REGEX:
        if re.search(pattern, payload):
            return True
    return False

# Route per l'invio di tutte le statistiche in tempo reale al grafico presente nel frontend
@app.before_request
def waf_filter():  # Usato per filtrare ogni richiesta prima che venga elaborata da una route.
   
    client_ip = request.remote_addr
    current_time = time.time()

    # Rate limiting 
    rate_limit_data[client_ip] = [t for t in rate_limit_data[client_ip] if t > current_time - RATE_PERIOD]
    if len(rate_limit_data[client_ip]) >= RATE_LIMIT:
        stats["total_requests"] += 1
        stats["rate_limit"] += 1
        socketio.emit('stats_update', stats)
        return jsonify({"error": "Rate limit exceeded"}), 429

    rate_limit_data[client_ip].append(current_time)

    # Analizza GET e POST
    if request.method in ["GET", "POST"]:
        for key, value in {**request.args, **request.form}.items():  # Rilevamento richieste malevole
            if is_malicious(value):
                stats["total_requests"] += 1
                stats["malicious_requests"] += 1
                stats["blocked_requests"] += 1

                # Invia le statistiche aggiornate tramite SocketIO
                socketio.emit('stats_update', stats)

                #return jsonify({"error": "Malicious request detected!"}), 403  
            
    # Se rileva un pattern malevolo, blocca la richiesta e aggiorna le statistiche.
    stats["total_requests"] += 1
    socketio.emit('stats_update', stats)
    return None

# Al posto di questa route mettere la route per renderizzare la pagina che sarà dedita al monitoring 
@app.route('/')
def home():

    #Mostra la pagina principale con il grafico.

    return render_template('index.html')


@app.route('/stats')
def get_stats():
    
    #API per ottenere le statistiche in formato JSON.
    
    return jsonify({
        "total_requests": stats["total_requests"],
        "malicious_requests": stats["malicious_requests"],
        "blocked_requests": stats["blocked_requests"],
        "rate_limit": stats["rate_limit"]
    })



# Queste route le ho usate per venificare che il grafico si aggiornasse

@app.route('/test-safe')
def test_safe():
    return jsonify({"message": "Questa è una richiesta sicura!"})


@app.route('/test-malicious-xss')
def test_malicious_xss():
    stats["malicious_requests"] += 1
    stats["blocked_requests"] += 1
    return jsonify({"message": "<script>alert('XSS')</script>"})



@app.route('/test-malicious-sql')
def test_malicious_sql():
    stats["malicious_requests"] += 1
    stats["blocked_requests"] += 1
    return jsonify({"message": "DROP TABLE users;"})

@app.route('/test-rate-limit')
def test_rate_limit():
    client_ip = request.remote_addr
    for _ in range(10):  # Simula 10 richieste rapide
        rate_limit_data[client_ip].append(time.time())
    return jsonify({"message": "Simula richieste multiple per testare il rate limit"})

# Aggiorna dashboard in tempo reale
@socketio.on('get_stats')
def send_stats():
    
    #Invia le statistiche aggiornate alla dashboard quando richiesto.
   
    socketio.emit('stats_update', stats)





@app.route('/Registrazione',methods=['GET','POST'])
def Registrazione():
    if request.method=='POST':
        name = request.form.get('name')
        lastname =request.form.get('lastname')
        username =request.form.get('username') 
        email =request.form.get('email')
        password =request.form.get('password')

        # Hash della password
        password_hash = generate_password_hash(password)
   
        # Salva l'utente nel database
        cursor=db.cursor()
        sql="INSERT INTO Registrazioni(Nome,Cognome,Email,Nome_Utente,Password_Utente) VALUES (%s,%s,%s,%s,%s)"
        values=(name,lastname,email,username,password_hash)
        cursor.execute(sql,values)
        db.commit()
        cursor.close()

        #inserire i nomi utenti e le password da registrazioni a accessi
        cursor=db.cursor()
        sql="INSERT INTO Accessii(Utente,Password) VALUES (%s,%s)"
        values=(username,password)
        cursor.execute(sql,values)
        db.commit()
        cursor.close()
    return render_template("Registrazione.html")

if __name__ == '__main__':
    socketio.run(app, debug=True)