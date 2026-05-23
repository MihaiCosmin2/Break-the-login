
from flask import Flask, request, render_template_string, redirect, url_for, session, make_response
import sqlite3
import os
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta


app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)


app.secret_key = "Very_PowerfulPasswordIWasBornIn2002" 

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=35)


serializer = URLSafeTimedSerializer(app.secret_key)

# functie pentru conectarea la baza de date
def acces_db():
    baza = sqlite3.connect('deskly.db')
    baza.row_factory = sqlite3.Row
    return baza

@app.route('/')
def home():
    if 'uid' in session:
        return render_template_string("""
            <h1>Deskly</h1>
            <p>Logat cu ID: {{ id }}</p>
            <ul>
                <li><a href="/tickets">Tichete CRUD</a></li>
                <li><a href="/logout">Iesire din cont</a></li>
            </ul> """, id=session['uid'], email=session.get('user_email'))
    return '<h1>Deskly versiune securizata</h1><a href="/login">Login</a> | <a href="/register">Creaza Cont</a>'


@app.route('/register', methods=['GET', 'POST'])
def inregistrare():
    if request.method == 'POST':
        mail = request.form.get('email')
        parola = request.form.get('password')
        
        # 4.1: Password Policy slab - Sunt acceptate parole foarte scurte sau triviale – Nu există validare la înregistrare
        # 4.2: Stocare nesigura a parolelor - Parole stocate în clar – Sau hash slab (MD5/SHA1)
        ######
        if len(parola) < 9:
            return "Parola trebuie sa aiba minim 9 caractere"
        if not re.search(r"[A-Z]", parola):
            return "Parola trebuie sa contina cel putin o litera mare"
        if not re.search(r"[a-z]", parola):
            return "Parola trebuie sa contna cel putin o litera mica"
        if not re.search(r"[0-9]", parola):
            return "Parola trebuie sa contina cel putin o cifra"
        ######

        salt = bcrypt.gensalt()
        parola_hashed = bcrypt.hashpw(parola.encode('utf-8'), salt).decode('utf-8')

        db = acces_db()
        try:
            db.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', 
                       (mail, parola_hashed, 'ANALYST'))
            db.commit()
            return redirect('/login')
        except:
            return "Eroare: Emailul e deja luat."
        finally:
            db.close()

    return '''
        <h4>Creeaza Cont Nou!</h4>
        <form method="post">
            Email: <input name="email"><br>
            Parola: <input name="password" type="password"><br>
            <button type="submit">Inregistrare</button>
                    </form> '''


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Incearca mai tarziu.")
def login():
    if request.method == 'POST':
        email_introdus = request.form.get('email')
        pass_introdus = request.form.get('password')
        # 4.3: Brute force / lipsă rate limiting: Număr nelimitat de încercări login – Fără blocare cont
        db = acces_db()
        
        try:
            om = db.execute('SELECT * FROM users WHERE email = ?', (email_introdus,)).fetchone()
        except:
            db.close()
            return "Eroare baza de date."

        # 4.4: User Enumeration - mesaje care ajuta atacatorul
        mesaj_eroare = "Autentificare esuata: Email sau parola incorecta."
        if not om:
            db.close()
            return mesaj_eroare
        
        hash_din_db = om['password_hash'].encode('utf-8')
        if bcrypt.checkpw(pass_introdus.encode('utf-8'), hash_din_db):
            session.permanent = True
            session['uid'] = om['id']
            session['user_email'] = om['email']
            session['role'] = om['role']

            db.execute('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
                       (om['id'], 'LOGIN', 'auth', request.remote_addr))
            db.commit()
            db.close()
            return redirect('/')
        else:
            db.close()
            return mesaj_eroare

    return '''
        <h4>Deskly versiune securizata</h4>
        <form method="post">
            Email: <input name="email"><br>
            Parola: <input name="password" type="password"><br>
            <button type="submit">Intra in contul tau!</button>
        </form>
        <br><a href="/forgot">Am uitat parola.</a>'''


@app.route('/tickets', methods=['GET', 'POST'])
def list_tickets():
    if 'uid' not in session: return redirect('/login')
    
    db = acces_db()
    
    if request.method == 'POST':
        titlu = request.form.get('title')
        descriere = request.form.get('description')
        
        db.execute('INSERT INTO tickets (title, description, severity, status, owner_id) VALUES (?, ?, ?, ?, ?)', 
                   (titlu, descriere, 'LOW', 'OPEN', session['uid']))
        
        db.execute('INSERT INTO audit_logs (user_id, action, resource) VALUES (?, ?, ?)', 
                   (session['uid'], 'CREATE_TICKET', 'tickets'))
        db.commit()

    bilete = db.execute('SELECT * FROM tickets WHERE owner_id = ?', (session['uid'],)).fetchall()
    db.close()
    
    html = '''
        <h4>Adauga Tichet Nou</h4>
        <form method="post">
            Titlu: <input name="title" required><br>
            Descriere: <input name="description" required><br>
            <button type="submit">Creeaza</button>
        </form>
        <hr>
        <h4>Toate Tichetele din Sistem</h4>
        <ul>
    '''
    for b in bilete:
        html += f"<li>[Owner ID: {b['owner_id']}] <b>{b['title']}</b> - Status: {b['status']}</li>"
    html += "</ul><a href='/'>Inapoi la Dashboard</a>"
    return html

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email')
        
        token_sigur = serializer.dumps(email, salt='resetare-parola-salt')
        
        print(f"\n(EMAIL) Catre: {email}\nLink resetare: http://127.0.0.1:5000/reset?token={token_sigur}\n")
        
        return "Daca adresa de email exista, vei primi un link."
    
    return 'Email: <form method="post"><input name="email"><button>Trimite token</button></form>'

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    token_introdus = request.args.get('token') or request.form.get('token')
    
    if not token_introdus:
        return "Error: Lipseste token-ul de resetare."

    try:
        email = serializer.loads(token_introdus, salt='resetare-parola-salt', max_age=900)
    except SignatureExpired:
        return "ERROR: Token-ul a expirat! Te rog cere altul."
    except BadSignature:
        return "ERROR: Token invalid sau manipulat."

    if request.method == 'POST':
        parola_noua = request.form.get('password')
        
        salt = bcrypt.gensalt()
        parola_noua_hashed = bcrypt.hashpw(parola_noua.encode('utf-8'), salt).decode('utf-8')
        
        db = acces_db()
        db.execute('UPDATE users SET password_hash = ? WHERE email = ?', (parola_noua_hashed, email))
        db.commit()
        db.close()
        
        return f"Parola a fost schimbata cu succes."

    return f'''
        <h3>Setare Parola Noua</h3>
        <form method="post">
            <input type="hidden" name="token" value="{token_introdus}">
            Parola Noua: <input name="password" type="password"><br>
            <button type="submit">Schimba Parola</button>
        </form>'''


if __name__ == '__main__':
    app.run(port=5000, debug=True)