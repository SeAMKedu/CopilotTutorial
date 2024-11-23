import math

class City:
    def __init__(self, name, region, population, latitude, longitude, area):
        self.name = name
        self.region = region
        self.population = int(population)
        self.latitude = float(latitude)
        self.longitude = float(longitude)
        self.area = float(area)

    def __str__(self):
        return f'{self.name} ({self.region}): {self.population}, Area: {self.area} km²'
