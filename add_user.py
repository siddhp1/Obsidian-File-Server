from app import app, db, User

def add_user(username, password):
    with app.app_context():
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

if __name__ == "__main__":
    add_user('username', 'password')