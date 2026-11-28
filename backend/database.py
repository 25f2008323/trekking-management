import sqlite3
from werkzeug.security import generate_password_hash

DB = "trekking.db"

def get_db_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    create table if not exists users(
    user_id integer primary key AUTOINCREMENT,
    name text NOT NULL,
    email text unique NOT NULL,
    password text NOT NULL,
    phone TEXT,
    gender text,
    dob date,
    status text default 'Active' CHECK(status in ('Active', 'Blacklisted')),
    created_at timestamp DEFAULT CURRENT_TIMESTAMP )""")

    cur.execute("""
    create table if not exists admins(
    admin_id integer primary key AUTOINCREMENT,
    username text UNIQUE NOT NULL,
    password text NOT NULL,
    email text UNIQUE NOT NULL
    )
    """)
    
    cur.execute("""
    create table if not exists staff(
    staff_id integer primary key AUTOINCREMENT,
    name text NOT NULL,
    email text unique NOT NULL,
    password text NOT NULL,
    phone text,
    experience integer DEFAULT 0,

    approval_status text DEFAULT 'Pending'
    CHECK(approval_status in ('Pending','Approved', 'Rejected', 'Blacklisted')),

    status text default 'Active'
    CHECK(status in ('Active', 'Blacklisted')),

    created_at timestamp DEFAULT current_timestamp
    )
     """)


    cur.execute("""
    create table if not exists treks(
    trek_id integer primary key AUTOINCREMENT,
    trek_name text NOT NULL,
    location text NOT NULL,
    
    difficulty text NOT NULL
        CHECK(difficulty in ('Easy', 'Moderate', 'Hard')),
    
    duration_days integer NOT NULL,
    total_slots integer NOT NULL,
    available_slots integer NOT NULL,
    description text,
    price real NOT NULL,
    status text DEFAULT 'Open' 
        CHECK(status in ('Open', 'Closed')),
    progress text default 'Not Started'
        CHECK(progress in ('Not Started', 'Started', 'Ongoing', 'Completed')),
    
    start_date date,
    end_date date,
    created_by_admin integer,
    created_at timestamp DEFAULT current_timestamp,

    foreign key(created_by_admin) references admins(admin_id)
    )
      """)

    cur.execute("""
    create table if not exists trek_assignments(
    assignment_id integer primary key AUTOINCREMENT,
    trek_id integer NOT NULL,
    staff_id integer NOT NULL,
    assigned_date timestamp DEFAULT current_timestamp,
    assigned_by_admin integer,

    foreign key(trek_id) references treks(trek_id)
    on DELETE cascade,
    
    foreign key(staff_id) references staff(staff_id) 
    on DELETE cascade,
    
    foreign key(assigned_by_admin) references admins(admin_id)
    )
      """)

    cur.execute("""
    create table if not exists bookings(
    booking_id integer primary key AUTOINCREMENT,
    user_id integer NOT NULL,
    trek_id integer NOT NULL,
    booking_date timestamp DEFAULT current_timestamp,
    number_of_people integer DEFAULT 1,
    
    status text DEFAULT 'Booked' CHECK(status in ('Booked', 'Cancelled', 'Completed')),
    payment_status text DEFAULT 'Pending' CHECK(payment_status in ('Pending', 'Paid', 'Failed')),
    
    foreign key (user_id) references users(user_id)
    on DELETE cascade,
    
    foreign key(trek_id) references treks(trek_id)
    on DELETE cascade
    
    )
      """)

    cur.execute("""
    create table if not exists activity_logs(
    log_id integer primary key AUTOINCREMENT,
    entity_type text NOT NULL,
    entity_id integer NOT NULL,
    
    admin_id integer NOT NULL,
    action text NOT NULL,
    remarks text,
    action_time timestamp DEFAULT current_timestamp,
    foreign key(admin_id) references admins(admin_id))""")


#     admin = conn.execute("""
#     SELECT admin_id, password
#     FROM admins
#     WHERE username = 'admin'
# """).fetchone()

#     if admin:
#         if not admin[1].startswith(("scrypt:", "pbkdf2:")):
#             conn.execute("""
#                 UPDATE admins
#                 SET password = ?
#                 WHERE admin_id = ?
#             """, (
#                 generate_password_hash(admin[1]),
#                 admin[0]
#             ))
#     else:
#         conn.execute("""
#             INSERT INTO admins (username, password, email)
#             VALUES (?, ?, ?)
#         """, (
#             "admin",
#             generate_password_hash("admin123"),
#             "admin@mail.com"
#         ))

    admin = conn.execute("""
        SELECT admin_id FROM admins WHERE username = ?
    """, ("admin",)).fetchone()

    if admin:
        conn.execute("""
            UPDATE admins
            SET password = ?
            WHERE admin_id = ?
        """, (
            generate_password_hash("admin123"),
            admin[0]
        ))
    else:
        conn.execute("""
            INSERT INTO admins (username, password, email)
            VALUES (?, ?, ?)
        """, (
            "admin",
            generate_password_hash("admin123"),
            "admin@mail.com"
        ))
    conn.commit()
    conn.close()

    print("Database created successfully.")

if __name__ == "__main__":
    init_db()  
