import math
from city import City

def calculate_distance(city1: City, city2: City) -> float:
    R = 6371  # Radius of the Earth in kilometers
    lat1, lon1 = math.radians(city1.latitude), math.radians(city1.longitude)
    lat2, lon2 = math.radians(city2.latitude), math.radians(city2.longitude)
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    distance = R * c
    return distance