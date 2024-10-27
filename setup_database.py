import sqlite3
import os

# Define the path to the new database location
db_path = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')

# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect(db_path)

# Create a cursor object to execute SQL commands
c = conn.cursor()

# Drop the keys table if it already exists
c.execute('DROP TABLE IF EXISTS keys;')

# Create the table with the required schema
c.execute('''
CREATE TABLE keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL  -- Store expiration time as a timestamp (UNIX time)
)
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

print(f"Database and table created successfully at {db_path}.")
