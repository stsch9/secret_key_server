import os
from model import db


# Delete database file if it exists currently
if os.path.exists("database.db"):
    os.remove("database.db")

# Create the database
db.create_all()