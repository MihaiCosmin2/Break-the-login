import sqlite3

def baza_date():
    connection = sqlite3.connect('deskly.db')
    tabel = connection.cursor()

    # tabel users
    tabel.execute("""
                  CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'USER',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    locked BOOLEAN DEFAULT 0        )
                  
""")
    
    tabel.execute(""" 
                    CREATE TABLE IF NOT EXISTS tickets        (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT,
                        severity TEXT CHECK( severity IN ('LOW', 'MED', 'HIGH') ),
                        status TEXT DEFAULT 'OPEN' CHECK( status IN ('OPEN', 'IN PROGRESS', 'RESOLVED') ),
                        owner_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP default CURRENT_TIMESTAMP,
                        FOREIGN KEY (owner_id) REFERENCES users(id)        )
""")
    
    tabel.execute(""" 
                CREATE TABLE IF NOT EXISTS audit_logs            (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    resource TEXT,
                    resource_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)    )
""")
    
    connection.commit()
    connection.close()

    print("Fisierul baza_date.py a mers.")

if __name__ == '__main__':
    baza_date()

