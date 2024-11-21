import math

class City:
    def __init__(self, name, region, population, latitude, longitude):
        self.name = name
        self.region = region
        self.population = int(population)
        self.latitude = float(latitude)
        self.longitude = float(longitude)

    # __str__ method is used to return a string representation of the object.
    def __str__(self):
        return f'{self.name} ({self.region}): {self.population}'

    # Calculate the distance between this city and another city
    def distance(self, other_city):
        # Haversine formula to calculate the distance between two points on the Earth
        R = 6371  # Radius of the Earth in kilometers
        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(other_city.latitude), math.radians(other_city.longitude)
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c
        return distance