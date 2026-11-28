from flask import Flask, render_template, request, redirect, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db
from database import get_db_connection
from flask_login import(LoginManager, UserMixin,login_user, logout_user,login_required,current_user)

from flask_cors import CORS
from functools import wraps
import os

app=Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-change-this"
)

app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
app.config["SESSION_COOKIE_SECURE"] = False

CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:5173"]
)

init_db()

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="user_login"

class User(UserMixin):
    def __init__(self,user_id,name,email,role):
        self.id=user_id
        self.name=name
        self.email=email
        self.role=role

@login_manager.user_loader
def load_user(user_id):
    conn=get_db_connection()
    user_id=str(user_id)

    if user_id.startswith("staff-"):

        staff_id=user_id.replace("staff-","")
        staff=conn.execute("""
        select * from staff where staff_id=?""",(staff_id,)).fetchone()

        conn.close()
    
        if staff:
            return User(f"staff-{staff['staff_id']}", staff["name"],staff["email"],"staff")
        return None
    
    elif user_id.startswith("admin-"):
        admin_id=user_id.replace("admin-","")
        admin=conn.execute("""select * from admins where admin_id=?
        """,(admin_id,)).fetchone()
        conn.close()

        if admin:
            return User(
                f"admin-{admin['admin_id']}",
                admin["username"],
                "",
                "admin"
            )
        return None  
    else:
        user=conn.execute("""
        select * from users where user_id=?""",(user_id,)).fetchone()
        conn.close()
        if user:
            return User(
                user["user_id"], user["name"], user["email"], "user"
            )      
        return None

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
               return jsonify({
                    "success": False,
                    "message": "Please login first"
                }), 401

            if current_user.role != required_role:
                return jsonify({
                    "success": False,
                    "message": "You are not authorized"
                }), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator
                

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register/user", methods=["GET", "POST"])
def register_user():
    if request.method=="POST":
        name=request.form["name"]
        email=request.form["email"]
        password=request.form["password"]

        if len(name)<3:
            return "Name must be at least 3 characters"
        if len(password)<4:
            return "Password should be at least 4 characters"
        conn=get_db_connection()
        password=generate_password_hash(password)
        check=conn.execute("""
        select * from users where email=?""",(email,)).fetchone()

        if check:
            conn.close()
            return "Email already registered"
        
        conn.execute("""
        insert into users(name, email, password) values(?,?,?)
        """, (name,email,password))

        conn.commit()
        conn.close()
        return redirect("/login/user")
    return render_template("register_user.html")


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data=request.get_json(silent=True) or {}
    name=data.get("name", "").strip()
    email=data.get("email", "").strip()
    password=data.get("password", "")

    if len(name)<3:
        return jsonify({
            "success":False,
            "message":"name must contain atleast 3 characters"
        }),400

    if not email or "@" not in email:
        return jsonify({
                    "success":False,
                    "message":"Enter a valid email"
                }),400
    if len(password)<8:
            return jsonify({
                "success":False,
                "message":"Password must contain atleast 8 characters"
            }),400
    conn=get_db_connection()
    
    existing_user=conn.execute("""
            select * from users where email=?""", (email,)).fetchone()
    staff=conn.execute("""
            select * from staff where email=?""",(email,)).fetchone()
    if existing_user or staff:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409
    hash_password=generate_password_hash(password)
    conn.execute("""
        insert into users(name, email, password) values(?,?,?)
        """, (name,email,hash_password))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Registration successful. Please login."
    }), 201


# @app.route("/api/auth/register", methods=["POST"])
# def api_register():
#     data=request.get_json(silent=True) or {}
#     name=data.get("name", "").strip()
#     email=data.get("email", "").strip()
#     password=data.get("password", "")

#     if len(name)<3:
#         return jsonify({
#             "success":False,
#             "message":"name must contain atleast 3 characters"
#         }),400

#     if not email or "@" not in email:
#         return jsonify({
#                     "success":False,
#                     "message":"Enter a valid email"
#                 }),400
#     if len(password)<8:
#             return jsonify({
#                 "success":False,
#                 "message":"Password must contain atleast 8 characters"
#             }),400
#     conn=get_db_connection()
    
#     existing_user=conn.execute("""
#             select * from users where email=?""", (email,)).fetchone()
#     staff=conn.execute("""
#             select * from staff where email=?""",(email,)).fetchone()
#     if existing_user or staff:
#         conn.close()

#         return jsonify({
#             "success": False,
#             "message": "Email already registered"
#         }), 409
#     hash_password=generate_password_hash(password)
#     conn.execute("""
#         insert into users(name, email, password) values(?,?,?)
#         """, (name,email,hash_password))

#     conn.commit()
#     conn.close()

#     return jsonify({
#         "success": True,
#         "message": "Registration successful. Please login."
#     }), 201

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data=request.get_json(silent=True) or {}
    role = data.get("role").strip().lower()
    name=data.get("name", "").strip()
    email=data.get("email", "").strip()
    password=data.get("password", "")
    
    if not password:
        return jsonify({
            "success":False,
            "message":"Password is required"
        }),400

    if role not in ("user", "staff", "admin"):
        return jsonify({
            "success": False,
            "message": "Invalid role"
        }), 400
    
    conn=get_db_connection()
    account=None
    valid_password=False
    logged_user=None
    if(role=="user"):
        account=conn.execute("""
                select * from users where email=?""", (email,)).fetchone()
        
        if account and account["status"] == "Blacklisted":
            conn.close()

            return jsonify({
                "success": False,
                "message": "Your account has been blacklisted"
            }), 403
        if account:
            if account["status"] == "Blacklisted":
                conn.close()
                return jsonify({
                    "success": False,
                    "message": "Your account has been blacklisted"
                }), 403

            valid_password = check_password_hash(
                account["password"], password
            )

            if valid_password:
                logged_user = User(
                    account["user_id"],
                    account["name"],
                    account["email"],
                    "user"
                )
    elif role=="staff":
        account = conn.execute("""
            SELECT * FROM staff WHERE email=?
        """, (email,)).fetchone()

        if account is None:
            conn.close()
            return jsonify({
                "success": False,
                "message": "Staff account not found"
            }), 401

        if account["approval_status"] != "Approved":
            conn.close()

            return jsonify({
                "success": False,
                "message": "Your staff account is not approved"
            }), 403

        if account["status"] == "Blacklisted":
            conn.close()

            return jsonify({
                "success": False,
                "message": "Your account has been blacklisted"
            }), 403

        valid_password = check_password_hash(
            account["password"], password
        )

        if valid_password:
            logged_user = User(
                f"staff-{account['staff_id']}",
                account["name"],
                account["email"],
                "staff"
            )
    
    elif role == "admin":
        username = data.get("username", "").strip()

        account = conn.execute("""
            SELECT * FROM admins WHERE username=?
        """, (username,)).fetchone()

        if account:
            valid_password = check_password_hash(
                account["password"], password
            )

            if valid_password:
                logged_user = User(
                    f"admin-{account['admin_id']}",
                    account["username"],
                    account["email"] if "email" in account.keys() else "",
                    "admin"
                )


    else:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Invalid role"
        }), 400

    conn.close()

    if account is None or not valid_password:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        }), 401

    login_user(logged_user)

    dashboard_routes = {
        "user": "/dashboard/trekker",
        "staff": "/dashboard/staff",
        "admin": "/dashboard/admin"
    }

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": str(logged_user.id),
            "name": logged_user.name,
            "email": logged_user.email,
            "role": logged_user.role
        },
        "redirect": dashboard_routes[logged_user.role]
    }), 200

@app.route("/api/auth/me", methods=["GET"])
def api_current_user():
    if not current_user.is_authenticated:
        return jsonify({
            "authenticated":False
        }),401
    return jsonify({
        "authenticated":True,
        "user":{
            "id":str(current_user.id),
            "name":current_user.name,
            "email":current_user.email,
            "role":current_user.role
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():

    logout_user()

    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })

@app.route("/api/admin/staff/create", methods=["POST"])
@role_required("admin")
def api_create_staff():
    data=request.get_json(silent=True) or {}
    name=data.get("name", "").strip()
    email=data.get("email", "").strip()
    password=data.get("password", "")

    if len(name)<3:
        return jsonify({
            "success":False,
            "message":"Invalid staff name"
        }),400

    if not email or "@" not in email:
        return jsonify({
                    "success":False,
                    "message":"Enter a valid email"
                }),400
    if len(password)<8:
            return jsonify({
                "success":False,
                "message":"Password must contain atleast 8 characters"
            }),400
    conn=get_db_connection()
    
    existing_user=conn.execute("""
            select user_id from users where email=?""", (email,)).fetchone()
    staff=conn.execute("""
            select staff_id from staff where email=?""",(email,)).fetchone()
    if existing_user or staff:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Email already exists"
        }), 409
    hash_password=generate_password_hash(password)
    conn.execute("""
        insert into staff(name, email, password, approval_status,status) values(?,?,?,'Approved','Active')
        """, (name,email,hash_password))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Staff account created successfully"
    }), 201



@app.route("/login/user", methods=["GET","POST"])
def user_login():
    if request.method=="POST":
        email=request.form["email"]
        password=request.form["password"]
        conn=get_db_connection()

        user=conn.execute("""
        select * from users where email=?""", (email,)).fetchone()
        conn.commit()
        conn.close()

        if not user:
            return "Invalid Credentials"
        if user["status"]=="Blacklisted":
            return "Your account has been blacklisted."
        if user and check_password_hash(user["password"], password):
            logged_user=User(
                user["user_id"],user["name"],user["email"],"user"
            )
            login_user(logged_user)
            return redirect("/user/dashboard")
        return "Invalid Credentials"
    return render_template("login_user.html")


@app.route("/login/staff", methods=["GET", "POST"])
def login_staff():
    if request.method=="POST":
        email=request.form["email"]
        password=request.form["password"]
        conn=get_db_connection()
        staff=conn.execute("""
        select * from staff where email=?""",(email,)).fetchone()
        conn.commit()
        conn.close()
        if not staff:
            return "Staff not found"
        if staff["approval_status"]=="Pending":
            return "Waiting for admin approval"
        if staff["approval_status"]=="Rejected":
            return "Registration Rejected"
        if staff["status"]=="Blacklisted":
            return "Your account has been blacklisted."
        if check_password_hash(staff["password"],password):
            logged_staff=User(
                f"staff-{staff['staff_id']}", staff["name"],staff["email"],"staff"
            )
            login_user(logged_staff)

            return redirect("/staff/dashboard")
        return "Invalid Credentials"
    return render_template("login_staff.html")

        
@app.route("/login/admin", methods=["GET","POST"])
def login_admin():
    if request.method=="POST":
        username=request.form["username"]
        password=request.form["password"]
        conn=get_db_connection()

        admin=conn.execute("""
                           
        select * from admins where username=?""", (username,)).fetchone()
        conn.commit()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            logged_admin=User(
                f"admin-{admin['admin_id']}",
                admin["username"],
                "",
                "admin"
            )
            login_user(logged_admin)
            return redirect("/admin/dashboard")
        return "Invalid Credentials"
    return render_template("login_admin.html")


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    total_users=conn.execute("""select count(*) from users""").fetchone()[0]
    total_staff=conn.execute("""select count(*) from staff""").fetchone()[0]
    total_treks=conn.execute("""select count(*) from treks""").fetchone()[0]
    total_bookings=conn.execute("""select count(*) from bookings""").fetchone()[0]

    conn.close()

    return render_template("admin_dashboard.html", total_users=total_users, total_staff=total_staff,total_treks=total_treks,total_bookings=total_bookings)


@app.route("/staff/dashboard")
@login_required
def staff_dashboard():
    if current_user.role!="staff":
        return "unauthorized", 403
    
    conn=get_db_connection()
    staff_id=current_user.id.replace("staff-", "")
    assigned_treks=conn.execute("""
    select t.trek_id, t.trek_name, t.location, t.status, t.progress, t.available_slots, count(b.booking_id) as registered_count
    from trek_assignments ta
    join treks t on ta.trek_id=t.trek_id
    left join bookings b on t.trek_id=b.trek_id
    where ta.staff_id=?
    group by t.trek_id, t.trek_name, t.location, t.status, t.progress, t.available_slots""", (staff_id,)).fetchall()
    conn.close()

    return render_template("staff_dashboard.html", assigned_treks=assigned_treks)

@app.route("/user/dashboard")
@login_required
def user_dashboard():
    if current_user.role!="user":
        return "unauthorized", 403
    return render_template("user_dashboard.html")


@app.route("/admin/pending")
@login_required
def pending_staff():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    staff_list=conn.execute("""
    select * from staff where approval_status='Pending'""").fetchall()
    conn.close()
    return render_template("pending_staff.html", staff_list=staff_list)


@app.route("/admin/approve/<int:staff_id>")
@login_required
def approve_staff(staff_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    update staff set approval_status='Approved' where staff_id=?""",(staff_id,))
    conn.execute("""
        Insert into activity_logs(
                    entity_type, entity_id, admin_id, action, remarks )
                    Values('Staff',?,?, 'Approved Staff','Staff approved')""",
                    (staff_id, current_user.id))

    conn.commit()
    conn.close()
    return redirect("/admin/pending")


@app.route("/admin/reject/<int:staff_id>")
@login_required
def reject_staff(staff_id):
    if current_user.role!= "admin":
        return "unauthorized", 403
    conn=get_db_connection()
    conn.execute("""
    update staff set approval_status='Rejected' where staff_id=?""",(staff_id,))
    conn.execute("""
        Insert into activity_logs(
                    entity_type, entity_id, admin_id, action, remarks )
                    Values('Staff',?,?, 'Rejected Staff','Staff rejected')""",
                    (staff_id, current_user.id))
    conn.commit()
    conn.close()
    return redirect("/admin/pending")


@app.route("/admin/treks/create", methods=["GET", "POST"])
@login_required
def create_trek():
    if current_user.role!="admin":
        return "unauthorized", 403
    if request.method=="POST":
        trek_name=request.form["trek_name"]
        location=request.form["location"]
        difficulty=request.form["difficulty"]
        duration_days=request.form["duration_days"]
        total_slots=request.form["total_slots"]
        description=request.form["description"]
        price=request.form["price"]
        start_date=request.form["start_date"]
        end_date=request.form["end_date"] 

        conn=get_db_connection()
        if int(duration_days)<=0:
            return "Duration must be greater than zero"
        
        if int(total_slots)<=0:
            return "Total slots must be greater than zero"
        
        if float(price)<=0:
            return "Price must be greater than zero"
        if start_date>=end_date:
            return "End date must be after start date"
        
        check=conn.execute("""
            select * from treks where trek_name=? and start_date=?""",(trek_name,start_date)).fetchone()
        
        if check:
            conn.close()
            return "This trek already exists"
        admin_id = int(current_user.id.replace("admin-", ""))
        conn.execute(""" Insert into treks (
                     trek_name, location, difficulty, duration_days, total_slots, available_slots, description, price, start_date, end_date, admin_id) 
                     Values(?,?,?,?,?,?,?,?,?,?,?)""",
                     (
                     trek_name,
            location,
            difficulty,
            duration_days,
            total_slots,
            total_slots,
            description,
            price,
            start_date,
            end_date,
            current_user.id))
        
        trek_id=conn.execute("Select last_insert_rowid()").fetchone()[0]
        conn.execute("""
        Insert into activity_logs(
                    entity_type, entity_id, admin_id, action, remarks )
                    Values('Trek',?,?, 'Created Trek',?)""",(
                        trek_id, current_user.id, trek_name
                    ))

        conn.commit()
        conn.close()

        return redirect("/admin/treks")
    return render_template("create_trek.html")

@app.route("/admin/treks")
@login_required
def admin_view_treks():
    if current_user.role!="admin":
        return "unauthorized", 403
    
    search=request.args.get("search","")

    conn=get_db_connection()
    treks=conn.execute("""
    select * from treks where trek_name like ?
    order by trek_id desc""",("%"+search+"%",)).fetchall()

    conn.close()
    return render_template("view_treks.html", treks=treks)

@app.route("/admin/treks/edit/<int:trek_id>", methods=["GET", "POST"])
@login_required
def edit_trek(trek_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    if request.method=="POST":
        trek_name=request.form["trek_name"]
        location=request.form["location"]
        difficulty=request.form["difficulty"]
        price=request.form["price"]
        
        if len(trek_name)<3:
            return "Invalid trek name"
        if float(price)<=0:
            return "Price must be greater than zero"

        conn.execute("""
        update treks set
        trek_name=?, location=?, difficulty=?, price=? where trek_id=?""",(
            trek_name, location, difficulty,price,trek_id
        ))

        conn.execute("""
        Insert into activity_logs(
                    entity_type, entity_id, admin_id, action, remarks )
                    Values('Trek',?,?, 'Updated Trek',?)""",(
                        trek_id, current_user.id, trek_name
                    ))


        conn.commit()
        
        conn.close()
        return redirect("/admin/treks")
    
    trek=conn.execute(""" select * from treks where trek_id=?""",(trek_id,)).fetchone()
    conn.close()

    return render_template("edit_trek.html", trek=trek)

@app.route("/admin/treks/delete/<int:trek_id>")
@login_required
def delete_trek(trek_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    delete from treks where trek_id=?""",(trek_id,))
    conn.execute("""
        Insert into activity_logs(
                    entity_type, entity_id, admin_id, action, remarks )
                    Values('Trek',?,?, 'Deleted Trek','Trek Removed')""",(
                        trek_id, current_user.id
                    ))

    conn.commit()
    conn.close()

    return redirect("/admin/treks")


@app.route("/admin/staff")
@login_required
def view_staff():
    if current_user.role!="admin":
        return "unauthorized", 403
    search=request.args.get("search","").strip()
    conn=get_db_connection()

    if search.isdigit():
        staff_list=conn.execute(""" 
        select * from staff where cast(staff_id as text) like ?
        """,(int(search),)).fetchall()
    else:    
        staff_list=conn.execute(""" 
        select * from staff where name like ?
        """,(f"%{search}%",)).fetchall()

    conn.close()
    return render_template("view_staff.html", staff_list=staff_list)

@app.route("/admin/staff/blacklist/<int:staff_id>")
@login_required
def blacklist_staff(staff_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    update staff set status ="Blacklisted" where staff_id=?""",(staff_id,))

    conn.commit()
    conn.close()

    return redirect("/admin/staff")

@app.route("/admin/staff/activate/<int:staff_id>")
@login_required
def activate_staff(staff_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    update staff set status ="Active" where staff_id=?""",(staff_id,))

    conn.commit()
    conn.close()

    return redirect("/admin/staff")

@app.route("/admin/assign", methods=["GET", "POST"])
@login_required
def assign_staff():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    if request.method=="POST":
        trek_id=request.form["trek_id"]
        staff_id=request.form["staff_id"]
        admin_id = int(current_user.id.replace("admin-", ""))
        check=conn.execute("""
        select * from trek_assignments where trek_id=? and staff_id=?""",(trek_id,staff_id)).fetchone()

        if check:
            conn.close()
            return "This staff member is already assigned to the trek"

        conn.execute("""
        insert into trek_assignments ( trek_id, staff_id, admin_id) VALUES(?,?,?)""",
        (trek_id, staff_id, current_user.id
        ))
        conn.commit()
        

        return redirect("/admin/assignments")
    
    treks=conn.execute(""" select * from treks""").fetchall()
    staff=conn.execute("""select * from staff where approval_status='Approved' AND status = 'Active' """).fetchall()

    conn.close()

    return render_template("assign_staff.html", treks=treks, staff=staff)


@app.route("/admin/assignments")
@login_required
def view_assignments():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    assignments=conn.execute("""
        select ta.assignment_id, t.trek_name, s.name as staff_name, ta.assigned_date
            from trek_assignments ta
            join treks t on ta.trek_id=t.trek_id
            join staff s on ta.staff_id=s.staff_id
            order by ta.assignment_id desc""").fetchall()
    
    conn.close()
    return render_template("view_assignments.html", assignments=assignments)

@app.route("/admin/users")
@login_required
def view_users():
    if current_user.role!="admin":
        return "unauthorized", 403
    
    search=request.args.get("search","").strip()
    conn=get_db_connection()

    if search.isdigit():
        users=conn.execute("""
        select * from users where user_id like ?""",(int(search),)).fetchall()
    else:    
        users=conn.execute("""select * from users where name like ?""",(f"%{search}%",)).fetchall()

    conn.close()

    return render_template("view_users.html", users=users)

@app.route("/admin/users/blacklist/<int:user_id>")
@login_required
def blacklist_user(user_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    update users set status ="Blacklisted" where user_id=?""",(user_id,))

    conn.commit()
    conn.close()

    return redirect("/admin/users")

@app.route("/admin/users/activate/<int:user_id>")
@login_required
def activate_user(user_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    
    conn=get_db_connection()
    conn.execute("""
    update users set status ="Active" where user_id=?""",(user_id,))

    conn.commit()
    conn.close()

    return redirect("/admin/users")

@app.route("/admin/bookings")
@login_required
def view_bookings():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    bookings=conn.execute("""
        select b.booking_id, u.name as user_name, t.trek_name, b.booking_date, b.number_of_people, b.status,b.payment_status
            from bookings b
            join users u on b.user_id=u.user_id
            join treks t on t.trek_id=b.trek_id
            order by b.booking_id desc     
          """).fetchall()
    conn.commit()
    conn.close()
    return render_template("view_bookings.html", bookings=bookings)

@app.route("/admin/history")
@login_required
def view_history():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    logs=conn.execute("""
    select * from activity_logs order by action_time desc""").fetchall()
    conn.commit()
    conn.close()

    return render_template("admin_history.html", logs=logs)

@app.route("/staff/trek/<int:trek_id>")
@login_required
def manage_trek(trek_id):
    if current_user.role!="staff":
        return "unauthorized", 403
    conn=get_db_connection()

    staff_id=current_user.id.replace("staff-", "")
    trek=conn.execute("""
    select * from treks t 
    join trek_assignments ta on t.trek_id=ta.trek_id
    where ta.staff_id=? and t.trek_id=?""",(staff_id,trek_id)).fetchone()

    conn.close()
    if trek is None:
        return "You are not assigned to this trek."
    
    return render_template("manage_trek.html", trek=trek)

@app.route("/staff/trek/<int:trek_id>/edit", methods=["GET", "POST"])
@login_required
def update_trek(trek_id):
    if current_user.role!="staff":
        return "unauthorized", 403
    conn=get_db_connection()

    staff_id=current_user.id.replace("staff-", "")
    trek=conn.execute("""
    select * from treks t 
    join trek_assignments ta on t.trek_id=ta.trek_id
    where ta.staff_id=? and t.trek_id=?
    """, (staff_id, trek_id)).fetchone()
    
    if trek is None:
        conn.close()
        return "You are not assigned to this trek."
    
    if request.method=="POST":
        available_slots=request.form["available_slots"]
        status=request.form["status"]
        progress=request.form["progress"]

        conn.execute("""
        update treks set available_slots=?, status=?, progress=? where trek_id=?""",(available_slots,status,progress,trek_id))

        if progress=="Completed":
            conn.execute("""
        Update bookings set status='Completed' where trek_id=?""",(trek_id,))

        conn.execute("""
        Update treks set available_slots=?, status=?, progress=? where trek_id=?""",
        (available_slots, status, progress, trek_id))

        conn.commit()
        conn.close()

        return redirect("/staff/dashboard")
    conn.close()
    return render_template("update_trek.html", trek=trek)

@app.route("/staff/trek/<int:trek_id>/participants")
@login_required
def view_participants(trek_id):
    if current_user.role!="staff":
        return "unauthorized", 403
    conn=get_db_connection()

    staff_id=current_user.id.replace("staff-", "")
    assignment=conn.execute("""
    select * from trek_assignments 
    where trek_id=?
    and staff_id=?""",(trek_id, staff_id)).fetchone()

    if assignment is None:
        conn.close()
        return "You are not assigned to this trek."
    
    participants=conn.execute("""
    select b.booking_id, u.name, u.email,u.phone, b.number_of_people,b.status,b.payment_status, b.booking_date
    from bookings b
    join users u on b.user_id=u.user_id
    where b.trek_id=?
    order by u.name""",(trek_id,)).fetchall()
    conn.close()
    return render_template("participants.html", participants=participants,trek_id=trek_id)

@app.route("/staff/trek/<int:booking_id>/complete")
@login_required
def complete_booking(booking_id):
    if current_user.role!="staff":
        return "unauthorized", 403
    
    conn=get_db_connection()
    staff_id=current_user.id.replace("staff-", "")

    booking=conn.execute("""
    select b.booking_id from bookings b
    join trek_assignments ta on ta.trek_id=b.trek_id
    where b.booking_id=? and ta.staff_id=?""",(booking_id,staff_id)).fetchone()

    if booking is None:
        conn.close()
        return "You are not authorized to perform this action"
    
    conn.execute("""
    Update bookings set status='Completed'
    where booking_id=?""",(booking_id,))

    conn.commit()
    conn.close()
    return redirect(request.referrer)

@app.route("/staff/profile", methods=["GET","POST"])
@login_required
def staff_profile():
    if current_user.role!="staff":
        return "unauthorized", 403
    
    staff_id = current_user.id.replace("staff-", "")
    conn=get_db_connection()
    staff=conn.execute("""
    select * from staff where staff_id=?
    """,(staff_id,)).fetchone()

    if request.method=="POST":
        name=request.form["name"]
        phone=request.form["phone"]
        experience=request.form["experience"]

        if len(name.strip())<3:
            return "Invalid name."
        if len(phone)!=10 or not phone.isdigit():
            return "Phone number must contain exactly 10 digits."

        if int(experience)<0:
            return "Experience cannot be negative."

        conn.execute("""
        update staff set name=?, phone=?,experience=?
        where staff_id=?""",
        (
            name,phone,experience,staff_id
        ))
        conn.commit()
        conn.close()

        return redirect("/staff/dashboard")
    conn.close()

    return render_template("staff_profile.html",staff=staff)

@app.route("/treks")
@login_required
def view_treks():
    if current_user.role!="user":
        return "Unauthorized", 403
    
    search=request.args.get("search", "")
    location=request.args.get("location","")
    difficulty= request.args.get("difficulty","")

    conn=get_db_connection()
    treks=conn.execute("""
        select * from treks where status='Open' and available_slots>0 and trek_name like ? and location like ? and difficulty like ?""",
        ("%"+search+"%","%"+location+"%","%"+difficulty+"%")).fetchall()
    conn.close()
    return render_template("view_treks.html", treks=treks,search=search,location=location,difficulty=difficulty)
    

@app.route("/book/<int:trek_id>", methods=["GET", "POST"])
@login_required
def book_trek(trek_id):
    if current_user.role!="user":
        return "unauthorized", 403
    
    conn=get_db_connection()
    trek=conn.execute("""
        select * from treks where trek_id=?""",(trek_id,)).fetchone()
    
    if trek is None:
        conn.close()
        return "Trek not found"
    if trek["status"]!="Open":
        conn.close()
        return "Booking for this trek is no longer available."
    
    if request.method=="POST":
        number_of_people=int(request.form["number_of_people"])

        if number_of_people<=0:
            conn.close()
            return "Invalid number of people."
        
        if number_of_people>trek["available_slots"]:
            conn.close()
            return "Only {} slot(s) available.".format(trek["available_slots"])
        
    
        existing_booking=conn.execute("""
            select * from bookings where user_id=? and trek_id=?""",
            (current_user.id, trek_id)).fetchone()
        
        if existing_booking:
            conn.close()
            return "You have already booked this trek."
    
        conn.execute("""
            insert into bookings (user_id, trek_id,number_of_people,status) values(
                    ?,?,?,?)""",(current_user.id, trek_id, number_of_people,"Booked"))

        conn.execute("""
            update treks set available_slots=available_slots-?
                where trek_id=?""",(number_of_people,trek_id,))
    
        conn.commit()
        conn.close()

        return redirect("/mybookings")
    conn.close()

    return render_template(
        "book_trek.html",
        trek=trek
    )


@app.route("/mybookings")
@login_required
def my_bookings():
    if current_user.role!="user":
        return "unauthorized", 403
    
    conn=get_db_connection()
    bookings=conn.execute(""" 
    select b.booking_id, b.status, b.booking_date, t.trek_name, t.location, t.difficulty, t.progress, t.status from bookings b
        join treks t on b.trek_id=t.trek_id where b.user_id=?""",(current_user.id,)).fetchall()
    conn.close()

    return render_template("my_bookings.html", bookings=bookings)

@app.route("/history")
@login_required
def trekking_history():
    if current_user.role!="user":
        return "unauthorized", 403
    
    conn=get_db_connection()

    bookings=conn.execute("""
    select b.booking_date, b.status, t.trek_name, t.location, t.progress from bookings b
        join treks t on b.trek_id=t.trek_id where b.user_id=? and t.progress='Completed'""",(current_user.id,)).fetchall()
    
    conn.close()
    return render_template("history.html", bookings=bookings)

@app.route("/user/profile", methods=["GET", "POST"])
@login_required
def update_profile():
    if current_user.role!="user":
        return "unauthorized", 403
    
    conn=get_db_connection()

    user=conn.execute("""
        select * from users where user_id=?""",(current_user.id,)).fetchone()
    message=None
    if request.method=="POST":
        name=request.form["name"]
        email=request.form["email"]
        phone=request.form["phone"]

        if len(name.strip())<3:
            return "Invalid Name"
        if len(phone)!=10 or not phone.isdigit():
            return "Phone number invalid"
        
        check=conn.execute("""
        select * from users where email=? and user_id!=?""",(email,current_user.id)).fetchone()

        if check:
            conn.close()
            return "Email already registered"
        conn.execute("""
        update users set name=?, email=?, phone=? where user_id=?""",
        (name, email, phone,current_user.id))
    
        conn.commit()
        user=conn.execute("""
        select * from users where user_id=?""",(current_user.id,)).fetchone()
        return redirect("/user/dashboard") 

    conn.close()
    return render_template("profile.html", user=user)

@app.route("/cancel/<int:booking_id>")
@login_required
def cancel_booking(booking_id):
    if current_user.role!="user":
        return "unauthorized", 403
    
    conn=get_db_connection()
    booking=conn.execute("""
    select * from bookings where booking_id=? and user_id=?""",(booking_id,current_user.id)).fetchone()

    if booking is None:
        conn.close()
        return "Booking not found"
    
    if booking["status"]!="Booked":
        conn.close()
        return "Only booked treks can be cancelled"
    
    conn.execute("""
        update bookings set status ='Cancelled' where booking_id=?""",(booking_id,))

    conn.execute("""
    update treks set available_slots=available_slots+?
    where trek_id=?""",(booking["number_of_people"],booking["trek_id"]))
    conn.commit()
    conn.close()

    return redirect("/mybookings")


@app.route("/admin/trek-history")
@login_required
def admin_trek_history():
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    history=conn.execute("""
    select u.name, t.trek_name, t.location, b.booking_date, b.status, t.progress from bookings b
    join users u on b.user_id=u.user_id
    join treks t on b.trek_id=t.trek_id
    order by b.booking_date desc""").fetchall()

    conn.close()

    return render_template("admin_trek_history.html", history=history)

# @app.route("/admin/treks/approve/<int:trek_id>")
# @login_required
# def approve_trek(trek_id):
#     if current_user.role!="admin":
#         return "unauthorized", 403
#     conn=get_db_connection()

#     conn.execute("""
#     update treks set approval_status='Approved' where trek_id=?""",(trek_id,))
#     conn.commit()
#     conn.close()

#     return redirect("/admin/treks")

# @app.route("/admin/treks/reject/<int:trek_id>")
# @login_required
# def reject_trek(trek_id):
#     if current_user.role!="admin":
#         return "unauthorized", 403
#     conn=get_db_connection()

#     conn.execute("""
#     update treks set approval_status='Rejected' where trek_id=?""",(trek_id,))
#     conn.commit()
#     conn.close()

#     return redirect("/admin/treks")


@app.route("/admin/treks/open/<int:trek_id>")
@login_required
def open_booking(trek_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()
    
    conn.execute("""
    update treks set status='Open' where trek_id=?""",(trek_id,))

    conn.commit()
    conn.close()

    return redirect("/admin/treks")

@app.route("/admin/treks/close/<int:trek_id>")
@login_required
def close_booking(trek_id):
    if current_user.role!="admin":
        return "unauthorized", 403
    conn=get_db_connection()

    conn.execute("""
    update treks set status='Closed' where trek_id=?""",(trek_id,))
    conn.commit()
    conn.close()

    return redirect("/admin/treks")
 

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


if __name__=="__main__":
    app.run(debug=True)