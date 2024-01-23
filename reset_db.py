# Script to reset the database
# Import the app and database
from app import app, db
# With the app
with app.app_context():
    # Create the database tables in the models file
    db.create_all()