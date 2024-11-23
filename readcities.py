import json
from city import City
from distance import calculate_distance

def read_cities(file_path):
    cities = []
    with open(file_path, 'r') as file:
        for line in file:
            name, region, population, latitude, longitude, area = line.strip().split(',')
            city = City(name, region, int(population), float(latitude), float(longitude), float(area))
            cities.append(city)
    return cities

def main():
    file_path = 'cities.txt'
    cities = read_cities(file_path)
    # sort cities by name
    cities = sorted(cities, key=lambda city: city.name)
    for city in cities:
        print(city)

    # calculate total population
    total_population = sum(city.population for city in cities)
    print('Total population:', total_population)

    # generate JSON file from the list of cities
    with open('cities.json', 'w') as json_file:
        json.dump([city.__dict__ for city in cities], json_file, indent=4)

    # calculate the distance between the first city and the other cities
    first_city = cities[0]
    for city in cities[1:]:
        distance = calculate_distance(first_city, city)
        print(f'Distance between {first_city.name} and {city.name}: {distance:.2f} km')

if __name__ == "__main__":
    main()
