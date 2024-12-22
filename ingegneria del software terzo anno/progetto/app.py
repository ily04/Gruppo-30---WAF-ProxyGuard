#importazione di librerie 
from email import errors 
from flask import Flask,request,render_template,redirect,url_for,flash
from werkzeug.security import generate_password_hash,check_password_hash 
import re
from validate_email_address import validate_email 
import mysql.connector 

# Inizializza l'app Flask   
app=Flask(__name__) #definiamo la variabile che è un istanza di flask dove name è semplicmemte il nome del file è cosi di standard non si cambia
app.config['SECRET_KEY']='CA87TYU'#inseriamo per sicurezza una chiave di sicurezza e deve essere dei byte

db=mysql.connector.connect(
       host="localhost",
       user="root",
       password="",
       database="pysql"
    )

@app.route('/', methods=['GET']) 
def index(): 
    return'<h2>Benvenuto nella nostra WEB APP :)</h2>\n <a href="/Accedi">Accedi</a>'

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
    if request.method=='POST':
        name=request.args.get('name') 
        password=request.args.get('password')
    return render_template('areaUser.html')

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
    
if __name__=='__main__':
    app.run(debug=True)
    





