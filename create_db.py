from app import db, User, Order, Role, generate_password_hash
def create_talbes():
    db.create_all()
    # admin_role =Role(role_name = "Admin")
    # User_role = Role(role_name = "User")
    hash_pw = generate_password_hash('Admin123',"sha256")
    x = User(first_name = 'Bilal', last_name = 'Sultan', email='bilal@sultan.com', hash_pw= hash_pw, role = admin_role)
    # db.session.add(admin_role)
    # db.session.add(User_role)
    db.session.add(x)
    db.session.commit()

create_talbes()