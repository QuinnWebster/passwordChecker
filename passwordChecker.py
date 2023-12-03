#!/usr/bin/env python3
# Import
import sys
import re

# Function to check if a password is valid
def checkPasswordValid(password):
    count = 1  # Set initial password security to one
    invalidLength = 0  # To keep track of if length is valid or not
    invalidChar = 0  # To keep track if characters are valid or not
    invalidString = ""  # Initialize a string that will say whether the password is valid

    lengthPattern = re.compile(r'^.{8,}$')  # Pattern that will check if 8+ characters
    properCharPattern = re.compile(r'^[ -~]+$')  # Pattern to check if valid characters

    if not lengthPattern.match(password):  # Check if password is 8+ length
        invalidLength = 1  # If so set invalidLength to one

    if not properCharPattern.match(password):  # Check if password only has valid characters
        invalidChar = 1  # If so set invalidChar to one

    if invalidLength == 1 and invalidChar == 1:  # If invalid length and invalid characters set string to corresponding message
        invalidString = "0,INVALID,TOO_SHORT,NONASCII"
        print(invalidString)  # Print the string
        return 0
    elif invalidLength == 1 and invalidChar == 0:  # If only too short, set string to corresponding message
        invalidString = "0,INVALID,TOO_SHORT"
        print(invalidString)  # Print message
        return 0
    elif invalidLength == 0 and invalidChar == 1:  # If only invalid characters set string to corresponding message
        invalidString = "0,INVALID,NONASCII"
        print(invalidString)  # Print corresponding message
        return 0

    return 1

# Function to check if there is an uppercase in the password
def checkUpperCase(password, count):
    upperCasePattern = re.compile(r'[A-Z]')  # Pattern to check for uppercase letters

    if upperCasePattern.search(password):  # If there is an uppercase increase count by one
        count += 1

    return count  # Return the new count

# Function to check if there is a lowercase in the password
def checkLowerCase(password, count):
    lowerCasePattern = re.compile(r'[a-z]')  # Pattern to check for lowercase letters

    if lowerCasePattern.search(password):  # If there is a lowercase increase count by 1
        count += 1

    return count  # Return the new count

# Function to check if there is a number in the password
def checkNumbers(password, count):
    numberPattern = re.compile(r'[0-9]')  # Pattern to check for a digit

    if numberPattern.search(password):  # If there is a digit increase count by 1
        count += 1

    return count  # Return new count

# Function to check if there is a special character in the password
def checkSpecialChar(password, count):
    specialCharPattern = re.compile(r'\W+')  # Pattern to check for a special character

    if specialCharPattern.search(password):  # If there is a special character increase count 1
        count += 1

    return count  # Return new count

# Function to check if there is a sequence of 3+ letters in the password
def checkSequence(password, count):
    sequencePattern = re.compile(r'(.)\1{2,}')  # Pattern to check for a sequence of 3+ letters

    if sequencePattern.search(password):  # If there is a sequence of 3+ letters decrease count by 1
        count -= 1

    return count  # Return new count

# Function to set string for how strong the password is
def getStrength(count):
    strengthString = ""

    # Depending on the value of the count, set the string to its corresponding strength
    if count == 1:
        strengthString = ",VERY_WEAK"
    elif count == 2:
        strengthString = ",WEAK"
    elif count == 3:
        strengthString = ",MEDIUM"
    elif count == 4:
        strengthString = ",STRONG"
    elif count == 5:
        strengthString = ",VERY_STRONG"

    return strengthString

def main():
    # if arguments provided, show error message
    if len(sys.argv) != 1:
        print("No arguments should be provided.")
        print("Usage: %s" % sys.argv[0])
        return 1

    # ADD YOUR CODE HERE

    for line in sys.stdin:  # For each line of standard input
        count = 1  # Initialize count to 1
        oldCount = count  # Initialize old count to have the same value as current count
        invalidTest = 0  # Set invalid test to 0
        validString = ""  # Initialize valid string
        strengthString = ""  # Initialize strength string

        password = line.strip()  # Make the current password
        invalidTest = checkPasswordValid(password)  # Check if the password is invalid
        count = checkUpperCase(password, count)  # Check for uppercase

        if count != oldCount:
            validString = validString + ",UPPERCASE"
            oldCount = count

        count = checkLowerCase(password, count)

        if count != oldCount:
            validString = validString + ",LOWERCASE"
            oldCount = count

        count = checkNumbers(password, count)

        if count != oldCount:
            validString = validString + ",NUMBER"
            oldCount = count

        count = checkSpecialChar(password, count)

        if count != oldCount:
            validString = validString + ",SPECIAL"
            oldCount = count

        count = checkSequence(password, count)

        if count != oldCount:
            validString = validString + ",sequence"
            # Have now checked all components that could add or subtract to the total strength on the password

        # Get the string representation of how strong the password is
        strengthString = getStrength(count)

       
       

        # If the password is valid
        if invalidTest != 0:
            validString = str(count) + strengthString + validString
            # Set the valid string to be the current count, the strength, and each component of the strength

            print(validString)  # Print the valid string

    return 0

if __name__ == "__main__":
    main()
