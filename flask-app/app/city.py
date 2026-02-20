
class City:
    def __init__(self, name, population, country):
        self.name = name
        self.country = country
        self.population = population

    def __repr__(self):
        return f"City(name='{self.name}', country='{self.country}', population={self.population})"

