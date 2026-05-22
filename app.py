
from flask import Flask, request, render_template_string, redirect, url_for, session, make_response
import sqlite3
import os

app = Flask(__name__)

# cheie vulnerabila
app.secret_key = "parola_simpla" 

app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None

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
    return '<h1>Deskly versiune vulnerabila</h1><a href="/login">Login</a> | <a href="/register">Creaza Cont</a>'


@app.route('/register', methods=['GET', 'POST'])
def inregistrare():
    if request.method == 'POST':
        mail = request.form.get('email')
        parola = request.form.get('password')
        
        # 4.1: Password Policy slab - Sunt acceptate parole foarte scurte sau triviale – Nu există validare la înregistrare
        # 4.2: Stocare nesigura a parolelor - Parole stocate în clar – Sau hash slab (MD5/SHA1)

        db = acces_db()
        try:
            db.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', 
                       (mail, parola, 'ANALYST'))
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
def login():
    if request.method == 'POST':
        email_introdus = request.form.get('email')
        pass_introdus = request.form.get('password')
        # 4.3: Brute force / lipsă rate limiting: Număr nelimitat de încercări login – Fără blocare cont
        db = acces_db()

        query = f"SELECT * FROM users WHERE email = '{email_introdus}'"
        
        try:
            om = db.execute(query).fetchone()
        except:
            db.close()
            return "Eroare, sql injection posibil"

        # 4.4: User Enumeration - mesaje care ajuta atacatorul
        if not om:
            db.close()
            return "USER_NOT_FOUND: Acest email nu exista in baza de date."
        
        if om['password_hash'] == pass_introdus:
            # 4.5: Gestionare nesigura a sesiunilor - Cookie fără HttpOnly / Secure / SameSite– Token cu expirare prea lungă
            session['uid'] = om['id']
            session['user_email'] = om['email']
            session['role'] = om['role']

            db.execute('INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',(om['id'], 'LOGIN', 'auth', request.remote_addr))
            db.commit()
            db.close()

            return redirect('/')
        else:
            db.close()
            return "WRNG_PASS: Parola introdusa este incorecta."

    return '''
        <h4>AuthX</h4>
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
    # vulnerabilitat IDOR
    bilete = db.execute('SELECT * FROM tickets').fetchall()
    db.close()
    
    html = "<h4>Tichete Suport</h4><ul>"
    for b in bilete:
        html += f"<li>{b['title']} - Status: {b['status']}</li>"
    html += "</ul><a href='/'>Inapoi</a>"
    return html

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        # 4.6: Resetare parola nesigura - Token predictibil, reutilizabil, fara expirare
        import time
        token_slab = str(int(time.time())) 
        return f"Daca userul exista, s-a trimis link-ul. (Debug: token-ul tau este {token_slab})"
    
    return 'Email: <form method="post"><input name="email"><button>Trimite token</button></form>'

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(port=5000, debug=True)