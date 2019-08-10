from flask import Flask, render_template, request, flash, redirect, url_for, session, logging, jsonify, make_response
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
import datetime
import jwt
from wtforms import Form, StringField, TextAreaField, PasswordField, DateTimeField, validators
import datetime
import config

app = Flask(__name__)

app.config['SECRET_KEY'] = config.secret

# Config MySQL
app.config['MYSQL_HOST'] = config.mysql['host']
app.config['MYSQL_USER'] = config.mysql['user']
app.config['MYSQL_PASSWORD'] = config.mysql['password']
app.config['MYSQL_DB'] = config.mysql['db']
app.config['MYSQL_CURSORCLASS'] = "DictCursor"
# init MYSQL
mysql = MySQL(app)

#----------------------Start: Authentication Endpoints---------------------#

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor to execute queries
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, password) VALUES(%s, %s, %s)", (name, email, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        return jsonify({"message":"Registration Successful"})
    return jsonify({"message":form.errors}), 400

# Login
@app.route('/login', methods=['POST'])
def login():
        # Get Form Fields
        email = request.form['email']
        inputted_password = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            data = cur.fetchone()
            real_password = data['password']
            # Compare Passwords
            if sha256_crypt.verify(inputted_password, real_password):
                # Credential matched
                token = jwt.encode({'email' : data['email'], 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY'])
                return jsonify({"token" : token.decode('UTF-8')})
            else:
                return jsonify({"error":"Wrong credential"}),400
            # Close connection
            cur.close()
        else:
            return jsonify({"error":"Email not found"}),404

# Decorator for protected routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' not in request.headers:
            return jsonify({"errors":"Token is missing"}), 400

        token = request.headers['Authorization']
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except jwt.ExpiredSignatureError:
            return jsonify({"errors":"Token is expired"}), 400
        except:
            return jsonify({"errors":"Token is invalid"}), 400
        return f(*args, **kwargs)
    return decorated

#----------------------End: Authentication Endpoints---------------------#

#----------------------Start: Customers Endpoints---------------------#

# Get youngest n customers
@app.route('/youngest_customers/<int:n>')
@token_required
def get_youngest_customers(n):
    # Create cursor
    cur = mysql.connection.cursor()
    cur.execute("select * from customers order by dob desc LIMIT %s", [n])
    customerToShow = cur.fetchall()
    return jsonify(customerToShow)
    # Close connection
    cur.close()

# Get all customers
@app.route('/customers')
@token_required
def get_customers():
    # Create cursor
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM customers")
    customerToShow = cur.fetchall()
    return jsonify(customerToShow)
    # Close connection
    cur.close()

# Customers Form for create and update
class CustomerForm(Form):
    name = StringField('Name', [validators.length(min=1, max=50)])
    dob = DateTimeField('DOB', [validators.DataRequired()])

# Get customer by id
@app.route('/customers/<string:id>')
@token_required
def get_customer(id):
    # Create cursor
    cur = mysql.connection.cursor()
    count = cur.execute("SELECT * FROM customers WHERE id = %s", [id])
    if count > 0:
        customerToShow = cur.fetchone()
        return jsonify(customerToShow)
    else:
        return jsonify({"error":"Customer not found"}),404
    # Close connection
    cur.close()

# Create customers
@app.route('/customers', methods=['POST'])
@token_required
def create_customers():
    form = CustomerForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        dob = form.dob.data
        updated_at = datetime.datetime.now()

        # Create cursor to execute queries
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO customers(name, dob, updated_at) VALUES(%s, %s, %s)", [name, dob, updated_at])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        return jsonify({"message":"Customer Added"})
    return jsonify({"message":form.errors}), 400

# Update customers
@app.route('/customers/<string:id>', methods=['POST'])
@token_required
def update_customers(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get customer by id
    customerToEdit = cur.execute("SELECT * FROM customers WHERE id = %s", [id])

    if customerToEdit > 0:
        form = CustomerForm(request.form)
        if request.method == 'POST' and form.validate():
            name = form.name.data
            dob = form.dob.data
            updated_at = datetime.datetime.now()

            # Create cursor to execute queries
            cur = mysql.connection.cursor()

            # Execute query
            cur.execute("UPDATE customers set name = %s, dob=%s, updated_at=%s WHERE id = %s", [name, dob, updated_at, id])

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            return jsonify({"message":"Customer Updated"})
        return jsonify({"message":form.errors}), 400
    else:
        return jsonify({"error":"Customer not found"}),404
    
# Delete customers
@app.route('/customers/<string:id>', methods=['DELETE'])
@token_required
def delete_customers(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get customer by id
    customerToDelete = cur.execute("SELECT * FROM customers WHERE id = %s", [id])

    if customerToDelete > 0:

        # Create cursor to execute queries
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("DELETE from customers WHERE id = %s", [id])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        return jsonify({"message":"Customer Deleted"})

    else:
        return jsonify({"error":"Customer not found"}),404

#----------------------End: Customers Endpoints---------------------#

class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=1, max=50)])
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

if __name__== '__main__':
    app.secret_key='secret'
    app.run(debug=True)
