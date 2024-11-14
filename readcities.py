def read_cities(file_path):
    cities = []
    with open(file_path, 'r') as file:
        for line in file:
            name, region, population, latitude, longitude = line.strip().split(',')
            city = {
                'name': name,
                'region': region,
                'population': int(population),
                'latitude': float(latitude),
                'longitude': float(longitude)
            }
            cities.append(city)
    return cities

def main():
    file_path = 'cities.txt'
    cities = read_cities(file_path)
    # sort cities by name
    cities = sorted(cities, key=lambda city: city['name'])
    for city in cities:
        print(city)

    # calculate total population
    total_population = sum(city['population'] for city in cities)
    print('Total population:', total_population)


if __name__ == "__main__":
    main()