from flask import render_template, redirect, url_for, request, flash
from app.forms import PopulationForm
from app import city_data, database
from app.city import City
import os
import requests
import random

# Constants for the weather dashboard
CITIES = ["San Diego", "New York", "Miami", "Las Vegas", "Seattle", "Denver", "New Haven"]


def get_weather_data():
    api_key = os.getenv('WEATHER_API_KEY')
    results = {}
    for city in CITIES:
        url = f'http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units=imperial'
        try:
            response = requests.get(url).json()
            results[city] = response['main']['temp']
        except:
            results[city] = 0
    return results


def init_app(app):
    @app.route('/')
    def home():
        return render_template('base.html', title="Weather Dashboard")


    @app.route('/temps')
    def temps():
        """Route 1: HTML List using Jinja2"""
        data = get_weather_data()
        return render_template('temps.html', weather_data=data)


    @app.route('/plot_temps')
    def plot_temps():
        """Route 2: Chart.js visualization"""
        data = get_weather_data()
        return render_template('chart.html', 
                               labels=list(data.keys()), 
                               values=list(data.values()))


    @app.route('/fruits')
    def fruits():
        fruits = ['Apple', 'Banana', 'Cherry', 'Dragonfruit']
        r = random.choice(fruits) 
        return f"Random fruit: {r}"



    @app.route('/population', methods=['GET', 'POST'])
    def population():
        form = PopulationForm()
        
        if form.validate_on_submit():
            city_name = form.city.data
            population_count = form.population.data
            country_name = form.country.data
            
            if database.insert_city(city_name, population_count, country_name):
                flash(f'Successfully added/updated {city_name}!', 'success')
            else:
                flash('Error adding city to database.', 'error')
            
            return redirect(url_for('population'))
        
        # Get all cities from database
        cities = database.get_all_cities()
        return render_template('population.html', form=form, cities=cities, population_data=city_data, title="Population Dashboard")



    @app.route('/population/delete/<int:city_id>', methods=['POST'])
    def delete_population(city_id):
        if database.delete_city(city_id):
            flash('City deleted successfully!', 'success')
        else:
            flash('Error deleting city.', 'error')
        return redirect(url_for('population'))



    @app.route('/cities', methods=['GET', 'POST'])
    def cities():
        form = PopulationForm()
        
        if form.validate_on_submit():
            city_name = form.city.data
            population_count = form.population.data
            country_name = form.country.data
            city_data[city_name] = population_count, country_name
            return redirect(url_for('cities'))
        
        return render_template('cities.html', cities=city_data, form=form)


    @app.route('/search/<city_name>', methods=['GET'])
    def search(city_name):
        cities = database.get_all_cities()
        city_info = next((c for c in cities if c['city'] == city_name), None)
        if city_info:
            return render_template('search.html', city=city_info)
        else:
            flash(f'City "{city_name}" not found in database.', 'error')
            return redirect(url_for('population'))

