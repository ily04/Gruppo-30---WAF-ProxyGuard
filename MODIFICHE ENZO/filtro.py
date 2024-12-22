from flask import Flask, abort, request, render_template, jsonify
import requests
import re
import json


#Creiamo un'istanza della classe Flask
app = Flask(__name__)

#Variabile globale per memorizzare l'URL del server di destinazione
serverDestinazione = "http://localhost:5000" # valore inizialmente di default

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

#Funzione per rilevare SQL Injection 
def sql_injection(value): #value stringa da controllare
    for pattern in regole_waf["sql_patterns"]:
        if re.search(pattern,value): #def search che trova possibili match tra value e regex
            sql_error = "SQL Injection rilevata"
            print(f"SQL Injection detected: {value}") #vedrò questo messaggio nel server perchè il server in modalità debug
            return sql_error
    return None #Se non c'è SQL Injection


#Funzione per rilevare XSS
def xss_attack(value):
    for pattern in regole_waf["xss_patterns"]:
        if re.search(pattern,value):
            xss_error = "XSS rilevata"
            print(f"XSS detected: {value}")
            return xss_error
    return None

#Funzione per sanificare l'input
def sanitize_input(value):
    sql_error = sql_injection(value) #mi salva qui il ritorno della funzione sql_injection
    if sql_error: #true se contiene un valore(qualsiasi cosa che non è none quindi)
        return render_template('errorPage.html',error_message = sql_error), 400 #Risposta con codice 400
    
    xss_error = xss_attack(value)
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

    if request.method == 'GET':
        params = request.args #parametri della query string
        print(f"GET request to:{url}")
        print(f"Parameters:{params}")

        for key, value in params.items():
            sanitized_value = sanitize_input(value) #sanifica ogni parametr
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
        
        sanitized_data = sanitize_input(data.decode('utf-8')) #sanifica i dati POST
        if isinstance(sanitized_data,tuple): #Se è un errore
            return sanitized_data #ritorna l'errore e blocca la richiesta

        try:
            response = requests.post(url, data=data,headers=headers)
            return (response.content, response.status_code, response.headers.items())
        except requests.exceptions.RequestException:
                abort(500, description="Errore nella richiesta POST al server di destinazione")



 
#Pagine per effettuare il login, effettuare la configurazione del WAF: scrivere front end login(connessione al database)
#front end della configurazione(configurazione del server di destinazione, possibilità per l'utente di avere regole personalizzabili)
@app.route('/', methods=['GET', 'POST'])  
def index():
    global serverDestinazione
    if request.method == 'POST':
        serverDestinazione = request.form.get('server_url', serverDestinazione)

    return render_template('areaUser.html', serverDestinazione = serverDestinazione)

@app.route('/favicon.ico')
def favicon():
    return '', 204  # Risposta vuota con codice di stato 204 (No Content)


 #Esegui l'App Flask
if __name__ == '__main__':
   app.run(debug=True)

#prova github
    


    


