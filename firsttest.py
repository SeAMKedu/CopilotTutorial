def main():
    names = []
    while True:
        name = input("Enter a name (or press Enter to finish): ")
        if name == '':
            break
        names.append(name)
    
    names.sort()
    print("Sorted names:")
    for name in names:
        print(name)

if __name__ == "__main__":
    main()