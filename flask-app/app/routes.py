from flask import render_template, redirect, url_for, request, flash
from app.forms import PopulationForm, SearchForm, DeleteCityForm
from app import cities, database
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
            
            # In-memory version 
            # city_obj = City(city_name, population_count, country_name)
            # cities.append(city_obj)
            
            # Database version (comment out for in-memory)
            database.insert_city(city_name, population_count, country_name)
            
            return redirect(url_for('population'))
        
        return render_template('population.html', form=form, title="Population Dashboard")



    @app.route('/view_all')
    def view_all():
        # In-memory version (uncomment for in-memory)
        # city_objects = cities
        
        # Database version (comment out for in-memory)
        db_cities = database.get_all_cities()
        city_objects = [City(row['city'], row['population'], row['country'] if row['country'] else '') for row in db_cities]
        
        return render_template('view_cities.html', cities=city_objects)


    @app.route('/search', methods=['GET', 'POST'])
    def search():
        form = SearchForm()
        city_found = None
        
        if form.validate_on_submit():
            search_name = form.city.data
            
            # In-memory version (uncomment for in-memory)
            # for city in cities:
            #     if city.name.lower() == search_name.lower():
            #         city_found = city
            #         break
            
            # Database version (comment out for in-memory)
            db_cities = database.get_all_cities()
            for row in db_cities:
                if row['city'].lower() == search_name.lower():
                    city_found = City(row['city'], row['population'], row['country'] if row['country'] else '')
                    break
        
        return render_template('search.html', form=form, city=city_found)


    @app.route('/delete_city', methods=['GET', 'POST'])
    def delete_city():
        form = DeleteCityForm()
        
        if form.validate_on_submit():
            city_name = form.city.data
            
            # In-memory version (uncomment for in-memory)
            # for i, city in enumerate(cities):
            #     if city.name.lower() == city_name.lower():
            #         cities.pop(i)
            #         break
            
            # Database version (comment out for in-memory)
            db_cities = database.get_all_cities()
            for row in db_cities:
                if row['city'].lower() == city_name.lower():
                    database.delete_city(row['id'])
                    break
            
            return redirect(url_for('view_all'))
        
        return render_template('delete_city.html', form=form)
