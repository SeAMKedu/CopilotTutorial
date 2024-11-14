# make a program that reads the employees from the file employees.txt
# and prints them to the screen

# create a class called Employee. Member variable are name, age, position, email, and salary
class Employee:
    def __init__(self, name, age, position, email, salary):
        self.name = name
        self.age = age
        self.position = position
        self.email = email
        self.salary = salary

    # define a function that serializes the object to a json string
    def to_json(self):
        import json
        return json.dumps(self.__dict__)

    def __str__(self):
        return f'{self.name} {self.age} {self.position} {self.email} {self.salary}'
    
def main():
    # open the file
    infile = open('persons.txt', 'r')

    # read the contents of the file
    file_contents = infile.read()

    # close the file
    infile.close()

    # read the lines of the file into a list of employees
    employees = []
    lines = file_contents.split('\n')
    for line in lines:
        parts = line.split(',')
        emp = Employee(
            name=parts[0],
            age=int(parts[1]),
            position=parts[2],
            email=parts[3],
            salary=float(parts[4])
        )
        employees.append(emp)

    # print the list of employees
    for emp in employees:
        print(emp)

    # serialize the list of employees to a json string
    import json
    json_string = json.dumps([emp.__dict__ for emp in employees])
    print(json_string)

    # calculate the average age of the employees
    total_age = sum(emp.age for emp in employees)
    average_age = total_age / len(employees)
    print(f'Average age of employees: {average_age}')
    
    # calculate the average salary of the employees
    total_salary = sum(emp.salary for emp in employees)
    average_salary = total_salary / len(employees)
    print(f'Average salary of employees: {average_salary}')

main()