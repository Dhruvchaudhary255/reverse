import pandas as pd
import matplotlib.pyplot as plt

# Path to your CSV file
file_path = 'Systolic1.csv'

# Read the CSV file into a DataFrame
df = pd.read_csv(file_path)

# Debug: Print column names
print("Columns in DataFrame:", df.columns)

# Set figure size for histograms
plt.figure(figsize=(15, 5))

# Blood Pressure Histogram
plt.subplot(1, 3, 1)
plt.hist(df['BloodPressure'], bins=10, color='blue', edgecolor='black')  # Replace with actual name
plt.title('Blood Pressure')
plt.xlabel('Blood Pressure')
plt.ylabel('Frequency')

# Age Histogram
plt.subplot(1, 3, 2)
plt.hist(df['Age'], bins=10, color='green', edgecolor='black')  # Replace with actual name
plt.title('Age')
plt.xlabel('Age')
plt.ylabel('Frequency')

# Weight Histogram
plt.subplot(1, 3, 3)
plt.hist(df['Weight'], bins=10, color='red', edgecolor='black')  # Replace with actual name
plt.title('Weight')
plt.xlabel('Weight')
plt.ylabel('Frequency')

# Adjust layout and display the plot
plt.tight_layout()
plt.show()
