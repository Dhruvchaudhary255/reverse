def factorial(n):
    """
    Calculate the factorial of a given number.
    
    Parameters:
        n (int): The number to calculate the factorial for.
    
    Returns:
        int: The factorial of the number.
    """
    if n < 0:
        return "Factorial is not defined for negative numbers."
    elif n == 0 or n == 1:
        return 1
    else:
        result = 1
        for i in range(2, n + 1):
            result *= i
        return result


# Input from the user
try:
    number = int(input("Enter a number to calculate its factorial: "))
    print(f"The factorial of {number} is: {factorial(number)}")
except ValueError:
    print("Please enter a valid integer.")