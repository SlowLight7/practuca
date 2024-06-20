from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///orders.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(150), nullable=False)
    equipment = db.Column(db.String(150), nullable=False)
    issue = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='в ожидании')
    assigned_to = db.Column(db.String(150), nullable=True)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    orders = Order.query.all()
    return render_template('index.html', orders=orders)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('index'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/create_order', methods=['GET', 'POST'])
def create_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        equipment = request.form['equipment']
        issue = request.form['issue']
        new_order = Order(customer_name=customer_name, equipment=equipment, issue=issue)
        db.session.add(new_order)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_order.html')

@app.route('/update_order/<int:id>', methods=['GET', 'POST'])
def update_order(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    order = Order.query.get_or_404(id)
    if request.method == 'POST':
        order.status = request.form['status']
        order.assigned_to = request.form['assigned_to']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('update_order.html', order=order)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
