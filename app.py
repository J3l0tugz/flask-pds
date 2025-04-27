from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from neomodel import StructuredNode, StringProperty, UniqueIdProperty, RelationshipTo, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
app.config['SECRET_KEY'] = 'anothersecretkey'
api = Api(app)
jwt = JWTManager(app)
blacklist = set()

# db.set_connection('neo4j://neo4j:password@:localhost:7687/')

class User(StructuredNode):
    uid = UniqueIdProperty()
    username = StringProperty(unique=True, required=True)
    password = StringProperty(required=True)
    filled_pds = RelationshipTo('PersonalDataSheet', 'FILLED_PDS')

class PersonalDataSheet(StructuredNode):
    uid = UniqueIdProperty()
    # PERSONAL INFORMATION
    surname = StringProperty(required=True)
    first_name = StringProperty(required=True)
    middle_name = StringProperty(required=True)
    birthdate = StringProperty(required=True)
    sex = StringProperty(required=True)
    civil_status = StringProperty(required=True)
    residential_address = StringProperty(required=True)
    zip_code = StringProperty(required=True)
    telephone = StringProperty(required=True)
    # FAMILY BACKGROUND
    spouse_name = StringProperty(required=True)
    occupation = StringProperty(required=True)
    employer_name = StringProperty(required=True)
    father_name = StringProperty(required=True)
    mother_name = StringProperty(required=True)
    # EDUCATIONAL BACKGROUND
    elementary_school = StringProperty(required=True)
    elementary_degree = StringProperty(required=True)
    elementary_year = StringProperty(required=True)
    elementary_honors = StringProperty(required=True)

    highschool_school = StringProperty(required=True)
    highschool_degree = StringProperty(required=True)
    highschool_year = StringProperty(required=True)
    highschool_honors = StringProperty(required=True)

    college_school = StringProperty(required=True)
    college_degree = StringProperty(required=True)
    college_year = StringProperty(required=True)
    college_honors = StringProperty(required=True)

    date_created = StringProperty(required=True)

class Register(Resource):
    def post(self):
        data = request.get_json()
        hushed_password = generate_password_hash(data['password'])
        try:
            user = User(username=data['username'], password=hushed_password).save()
            return {'message': 'User  Registered Successfully'}, 201
        except Exception as e:
            return {'error': str(e)}, 400
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.nodes.first_or_none(username=data['username'])
        if user and check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.username)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401
    
class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        blacklist.add(jti)
        return {'message': 'Successfully logged out'}, 200

class Dashboard(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            pds_list = user.filled_pds.all()
            pds_data = []
            for pds in pds_list:
                pds_data.append({
                    'uid': pds.uid,
                    'surname': pds.surname,
                    'first_name': pds.first_name,
                    'middle_name': pds.middle_name,
                    'sex': pds.sex,
                    'quarter': pds.tele,

                    'date_created': pds.date_created
                })
            json = jsonify('pds_data')
            response = {'username': current_user, 'data': pds_data}
            return response
        
        return {'message': 'User  not found'}, 404

    
class PersonalDataSheetForm(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'username': current_user}, 200

class AddPersonalDataSheet(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            pds = PersonalDataSheet(
                surname=data['surname'],
                first_name=data['first_name'],
                middle_name=data['middle_name'],
                birthdate = data['birthdate'],  
                sex = data['sex'],
                civil_status = data['civil_status'],
                residential_address = data['residential_address'],
                zip_code = data['zip_code'],
                telephone = data['telephone'],
                
                spouse_name = data['spouse_name'],
                occupation = data['occupation'],
                employer_name = data['employer_name'],
                father_name = data['father_name'],
                mother_name = data['mother_name'],
                
                elementary_school = data['elementary_school'],
                elementary_degree = data['elementary_degree'],
                elementary_year = data['elementary_year'],
                elementary_honors = data['elementary_honors'],

                highschool_school = data['highschool_school'],
                highschool_degree = data['highschool_degree'],
                highschool_year = data['highschool_year'],
                highschool_honors = data['highschool_honors'],

                college_school = data['college_school'],
                college_degree = data['college_degree'],
                college_year = data['college_year'],
                college_honors = data['college_honors'],

                date_created=data['date_created']
            ).save()
            user.filled_pds.connect(pds)
            return {'message': 'Personal Data Sheet added successfully'}, 201
        return {'message': 'User  not found'}, 404

class GetPersonalDataSheet(Resource):
    @jwt_required()
    def get(self, pds_id):
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            pds = PersonalDataSheet.nodes.get_or_none(uid=pds_id)

            if pds and pds in user.filled_pds.all():
                data = {
                    'uid': pds.uid,
                    'surname': pds.surname,
                    'first_name': pds.first_name,
                    'middle_name': pds.middle_name,
                    'birthdate': pds.birthdate,
                    'sex': pds.sex,
                    'civil_status': pds.civil_status,
                    'residential_address': pds.residential_address,
                    'zip_code': pds.zip_code,
                    'telephone': pds.telephone,
                    'spouse_name': pds.spouse_name,
                    'occupation': pds.occupation,
                    'employer_name': pds.employer_name,
                    'father_name': pds.father_name,
                    'mother_name': pds.mother_name,
                    
                    'elementary_school': pds.elementary_school,
                    'elementary_degree': pds.elementary_degree,
                    'elementary_year': pds.elementary_year,
                    'elementary_honors': pds.elementary_honors,

                    'highschool_school': pds.highschool_school,
                    'highschool_degree': pds.highschool_degree,
                    'highschool_year': pds.highschool_year,
                    'highschool_honors': pds.highschool_honors,

                    'college_school': pds.college_school,
                    'college_degree': pds.college_degree,
                    'college_year': pds.college_year,
                    'college_honors': pds.college_honors,

                    'date_created': pds.date_created}
                
                return {'username': current_user, 'data': data}, 200
            
            return {'message': 'Personal Data Sheet not found or does not belong to the user'}, 404
        
        return {'message': 'User  not found'}, 404
    
class UpdatePersonalDataSheet(Resource):
    @jwt_required()
    def post(self, pds_id):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            pds = PersonalDataSheet.nodes.get_or_none(uid=pds_id)

            if pds and pds in user.filled_pds.all():                
                pds.surname=data.get('surname', pds.surname),
                pds.first_name = data.get('first_name', pds.first_name),
                pds.middle_name=data.get('middle_name', pds.middle_name),
                pds.birthdate = data.get('birthdate', pds.birthdate),  
                pds.sex = data.get('sex', pds.sex),
                pds.civil_status = data.get('civil_status', pds.civil_status),
                pds.residential_address = data.get('residential_address', pds.residential_address),
                pds.zip_code = data.get('zip_code', pds.zip_code),
                pds.telephone = data.get('telephone', pds.telephone),
                
                pds.spouse_name = data.get('spouse_name', pds.spouse_name),
                pds.occupation = data.get('occupation', pds.occupation),
                pds.employer_name = data.get('employer_name', pds.employer_name),
                pds.father_name = data.get('father_name', pds.father_name),
                pds.mother_name = data.get('mother_name', pds.mother_name),
                
                pds.elementary_school = data.get('elementary_school', pds.elementary_school),
                pds.elementary_degree = data.get('elementary_degree', pds.elementary_degree),
                pds.elementary_year = data.get('elementary_year', pds.elementary_year),
                pds.elementary_honors = data.get('elementary_honors', pds.elementary_honors),

                pds.highschool_school = data.get('highschool_school', pds.highschool_school),
                pds.highschool_degree = data.get('highschool_degree', pds.highschool_degree),
                pds.highschool_year = data.get('highschool_year', pds.highschool_year),
                pds.highschool_honors = data.get('highschool_honors', pds.highschool_honors),

                pds.college_school = data.get('college_school', pds.college_school),
                pds.college_degree = data.get('college_degree', pds.college_degree),
                pds.college_year = data.get('college_year', pds.college_year),
                pds.college_honors = data.get('college_honors', pds.college_honors),

                pds.date_created=data.get('date_created', pds.date_created)
                pds.save() 

                return {'message': 'Personal Data Sheet updated successfully'}, 200
            
            return {'message': 'Personal Data Sheet not found or does not belong to the user'}, 404
        
        return {'message': 'User  not found'}, 404

class DeletePersonalDataSheet(Resource):
    @jwt_required()
    def get(self, pds_id):
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            pds = PersonalDataSheet.nodes.get_or_none(uid=pds_id)

            if pds and pds in user.filled_pds.all():
                pds.delete()
                return {'message': 'Personal Data Sheet deleted successfully'}, 200
            
            return {'message': 'Personal Data Sheet not found or does not belong to the user'}, 404
        
        return {'message': 'User  not found'}, 404

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Dashboard, '/dashboard')
api.add_resource(PersonalDataSheetForm, '/pds-form')
api.add_resource(AddPersonalDataSheet, '/add-pds')
api.add_resource(GetPersonalDataSheet, '/get-pds/<pds_id>')
api.add_resource(UpdatePersonalDataSheet, '/update-pds/<pds_id>')
api.add_resource(DeletePersonalDataSheet, '/delete-pds/<pds_id>')


if __name__ == '__main__':
    app.run(port=4000, debug=True)