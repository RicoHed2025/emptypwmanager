import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    """
    Check if a password is strong.

    A strong password:
    - Is at least 8 characters long
    - Contains at least one uppercase letter, 
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least  one special character

    Returns:
        bool: True if the password is strong, False otherwise.
    """

    shortcomings = []  # List to store shortcomings

    # Check length
    if len(password) < 8:
        shortcomings.append("Password must be at least 8 characters long.")

    # Check for required character types
    if not any(char.isupper() for char in password):
        shortcomings.append("Password must contain at least one uppercase letter.")
    if not any(char.islower() for char in password):
        shortcomings.append("Password must contain at least one lowercase letter.")
    if not any(char.isdigit() for char in password):
        shortcomings.append("Password must contain at least one digit.")
    if not any(not char.isalnum() for char in password):
        shortcomings.append("Password must contain at least one special character.")

    # Print shortcomings if any
    if shortcomings:
        print("Password is not strong:")
        for issue in shortcomings:
            print(f"- {issue}")
        return False
    
    print("Password is strong!")
    return True

# Password generator function (optional)
def generate_password(length):
    """
    Generate a random strong password of the specified length.
    The password will include uppercase letters, lowercase letters, digits,
    and special characters, but will exclude whitespace.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """
    if length < 8:
        print("Password length should be at least 8 characters.")
        return ""

    all_chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

    # Character set excluding whitespace
    char_set= string.ascii_letters + string.digits + string.punctuation
    password = ""
    for i in range(length):
        password += random.choice(char_set)

    #REMOVE print when done
    print(password) 
    return password    

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []
shift = []

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.

    This function should prompt the user for the website, username,  and password 
    and store them to lists with same index. Optionally, it should check password strengh 
    with the function is_strong_password. It may also include an option for the user to
    generate a random strong password by calling the generate_password function.

    Returns:
        None
    """
    website = input("Eter the website: ")

    username = input("Enter your username: ")


    while True:
        choice = input("Do you want to generate a random strong password? (yes/no): ").strip().lower()
        if choice == "yes":
            while True:
                try:
                    length = int(input("Enter the desired password length (8 or higher): "))
                    if length < 8:
                        print("Password length must be at least 8 characters. Please try again.")
                    else:
                        break
                except ValueError:
                    print("Invalid input. Please enter a number.")
            password = generate_password(length)
            print(f"Generated password: {password}")
            break
        elif choice == "no":
            password = input("Enter your password: ")
            if is_strong_password(password):
                break
            else:
                print("Please try again with a stronger password.")
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")

    # Encrypt and store the password        
    random_shift = random.randint(1, 25)
    encrypted_passwords.append(caesar_encrypt(password, random_shift))  # Encrypt the password with a random shift
    websites.append(website)
    usernames.append(username)
    shift.append(random_shift)    

    print(encrypted_passwords)
    print(websites)
    print(usernames)
    print(shift)

    return None

# Function to retrieve a password 
def get_password():

 
    website = input("Enter website name to retrieve password: ")
    if website in websites:
        index = websites.index(website)
        shift = 3
        decrypted = caesar_decrypt(encrypted_passwords[index], shift)
        print(f"Username: {usernames[index]}")
        print(f"Password: {decrypted}")
    else:
        print("Website not found.")

# Function to save passwords to a JSON file 
def save_passwords():

    passworddata = {
        "Website": websites,
        "username": usernames,
        "encrypted_password": encrypted_passwords

    }
    path = "passwords.json"
    try:

        with open(path, "w") as file:
            json.dump(passworddata, file, indent=4)
            print(f"json file '{path}' was created")
    except FileExistsError:
            print ("already exist")
    pass


# Function to load passwords from a JSON file 
def load_passwords():
    path1 = "passwords.json"
    try:
        with open(path1, "r") as file:
            data = json.load(file)
            # Replace the contents of the lists
            global websites, usernames, encrypted_passwords
            websites = data.get("website")
            usernames = data.get("username")
            encrypted_passwords = data.get("encrypted_password")
    except FileNotFoundError:
        print(f"'{path1}' not found. No data loaded.")
    except Exception as e:
        print(f"An error occurred{e}")
    return print(data)

# Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
    print("1. Add Password")
    print("2. Get Password")
    print("3. Save Passwords")
    print("4. Load Passwords")
    print("5. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        save_passwords()
    elif choice == "4":
        load_passwords()
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()
