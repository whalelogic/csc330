from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired

class PopulationForm(FlaskForm):
    city = StringField('City:', validators=[DataRequired()])
    country = StringField('Country:', validators=[DataRequired()])
    population = IntegerField('Population: ', validators=[DataRequired()])
    submit = SubmitField('Save')

class SearchForm(FlaskForm):
    city = StringField('City Name:', validators=[DataRequired()])
    submit = SubmitField('Search')

class DeleteCityForm(FlaskForm):
    city = StringField('City Name:', validators=[DataRequired()])
    submit = SubmitField('Delete')
