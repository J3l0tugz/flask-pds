from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_restful import Api, Resource
from neomodel import StructuredNode, StringProperty, UniqueIdProperty, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
import requests

app = Flask(__name__)

client_app = Flask(__name__)
client_app.config['SECRET_KEY'] = 'clientsecretkey'
AUTH_SERVER = 'http://127.0.0.1:4000'

@client_app.route('/')
def home():
    return render_template('login.html')

@client_app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {'username': request.form['username'], 'password': request.form['password']}
        response = requests.post(f'{AUTH_SERVER}/register', json=data)

        print(f'test {data}')

        if response.status_code == 201:
            return redirect(url_for('login'))
        return jsonify(response.json()), response.status_code
    return render_template('register.html')

@client_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {'username': request.form['username'], 'password': request.form['password']}
        response = requests.post(f'{AUTH_SERVER}/login', json=data)
        if response.status_code == 200:
            session['token'] = response.json().get('access_token')
            return redirect(url_for('dashboard'))
        flash('Incorrect Username or Password')
        return redirect(url_for('login'))
        # return jsonify(response.json()), response.status_code
    return render_template('login.html')

@client_app.route('/logout', methods=['POST', 'GET'])
def logout():
    token = session.get('token')
    headers = {'Authorization': f'Bearer {token}'}
    reponse = requests.post(f'{AUTH_SERVER}/logout', headers=headers)

    session.pop('token', None)
    return redirect(url_for('login'))

@client_app.route('/dashboard')
def dashboard():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{AUTH_SERVER}/dashboard', headers=headers)
    if response.status_code == 200:
        return render_template('dashboard.html', username=response.json().get('username'), data_sheets=response.json().get('data'))
    return redirect(url_for('login'))

@client_app.route('/pds-form')
def pdsForm():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{AUTH_SERVER}/pds-form', headers=headers)
    if response.status_code == 200:
        return render_template('pds-form.html', username=response.json().get('username'))
    return redirect(url_for('dashboard'))

@client_app.route('/add-pds', methods = ['POST', 'GET'])
def addpds():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    if request.method == 'POST':
        headers = {'Authorization': f'Bearer {token}'}
        now = datetime.now()
        data = {
                    'surname': request.form['surname'],
                    'first_name': request.form['first_name'],
                    'middle_name': request.form['middle_name'],
                    'birthdate': request.form['birthdate'],
                    'sex': request.form['sex'],
                    'civil_status': request.form['civil_status'],
                    'residential_address': request.form['residential_address'],
                    'zip_code': request.form['zip_code'],
                    'telephone': request.form['telephone'],
                    'spouse_name': request.form['spouse_name'],
                    'occupation': request.form['occupation'],
                    'employer_name': request.form['employer_name'],
                    'father_name': request.form['father_name'],
                    'mother_name': request.form['mother_name'],
                    
                    'elementary_school': request.form['elementary_school'],
                    'elementary_degree': request.form['elementary_degree'],
                    'elementary_year': request.form['elementary_year'],
                    'elementary_honors': request.form['elementary_honors'],

                    'highschool_school': request.form['highschool_school'],
                    'highschool_degree': request.form['highschool_degree'],
                    'highschool_year': request.form['highschool_year'],
                    'highschool_honors': request.form['highschool_honors'],

                    'college_school': request.form['college_school'],
                    'college_degree': request.form['college_degree'],
                    'college_year': request.form['college_year'],
                    'college_honors': request.form['college_honors'],

                    'date_created': now.strftime('%m/%d/%Y')}
        response = requests.post(f'{AUTH_SERVER}/add-pds', headers=headers, json=data)
        if response.status_code == 201:
            flash('Added Personal Data Sheet', 'success')
            return redirect(url_for('dashboard'))
        flash('Error while adding Personal Data Sheet', 'danger')
        return redirect(url_for('pdsForm'))

@client_app.route('/get-pds/<pds_id>', methods=['POST', 'GET'])
def getpds(pds_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    if request.method == 'GET':
        response = requests.get(f'{AUTH_SERVER}/get-pds/{pds_id}', headers=headers)
        if response.status_code == 200:
            return render_template('view-form.html', username=response.json().get('username'), data=response.json().get('data'))
        return redirect(url_for('dashboard'))
    
@client_app.route('/update-pds/<pds_id>', methods=['POST', 'GET'])
def updatepds(pds_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    if request.method == 'POST':
        headers = {'Authorization': f'Bearer {token}'}
        data = {
                    'surname': request.form['surname'],
                    'first_name': request.form['first_name'],
                    'middle_name': request.form['middle_name'],
                    'birthdate': request.form['birthdate'],
                    'sex': request.form['sex'],
                    'civil_status': request.form['civil_status'],
                    'residential_address': request.form['residential_address'],
                    'zip_code': request.form['zip_code'],
                    'telephone': request.form['telephone'],
                    'spouse_name': request.form['spouse_name'],
                    'occupation': request.form['occupation'],
                    'employer_name': request.form['employer_name'],
                    'father_name': request.form['father_name'],
                    'mother_name': request.form['mother_name'],
                    
                    'elementary_school': request.form['elementary_school'],
                    'elementary_degree': request.form['elementary_degree'],
                    'elementary_year': request.form['elementary_year'],
                    'elementary_honors': request.form['elementary_honors'],

                    'highschool_school': request.form['highschool_school'],
                    'highschool_degree': request.form['highschool_degree'],
                    'highschool_year': request.form['highschool_year'],
                    'highschool_honors': request.form['highschool_honors'],

                    'college_school': request.form['college_school'],
                    'college_degree': request.form['college_degree'],
                    'college_year': request.form['college_year'],
                    'college_honors': request.form['college_honors'],}
        response = requests.post(f'{AUTH_SERVER}/update-pds/{pds_id}', headers=headers, json=data)
        if response.status_code == 200:
            flash('Updated pds', 'success')
            return redirect(url_for('dashboard'))
        flash('Error while updating pds', 'danger')
        return redirect(url_for('getpds', pds_id=pds_id))
    
@client_app.route('/delete-pds/<pds_id>')
def deletepds(pds_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{AUTH_SERVER}/delete-pds/{pds_id}', headers=headers)
    if response.status_code == 200:
        flash('Deleted pds', 'success')
        return redirect(url_for('dashboard'))
    flash('Erro while deleting pds', 'danger')
    return jsonify(response.json()), response.status_code

if __name__ == '__main__':
    client_app.run(port=4001, debug=True)