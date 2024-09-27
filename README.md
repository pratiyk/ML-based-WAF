# ML-based-WAF
This project implements a machine learning-based Web Application Firewall (WAF) to enhance the security of web applications. The WAF uses advanced algorithms to detect and mitigate various types of web attacks, such as SQL injection, cross-site scripting (XSS), and other malicious requests.

### Classifier
```
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# Load the combined dataset
data = pd.read_csv('combined_parsed_requests.csv')

# Sample a smaller subset of the data
data = data.sample(frac=0.1, random_state=42)  # Use 10% of the dataset

# Define features and target
feature_columns = data.columns.drop('request_type')
X = data[feature_columns]
y = data['request_type']

# One-hot encode categorical features
X_encoded = pd.get_dummies(X, drop_first=True)

# Initial split of the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.3, random_state=42)

# Create a Random Forest classifier
model = RandomForestClassifier(random_state=42)

# Adjusted hyperparameter tuning using GridSearchCV
param_grid = {
    'n_estimators': [100],  # Reduced number of estimators
    'max_depth': [None, 10],  # Limited options
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1],
    'max_features': ['sqrt', 'log2']  # Use valid options
}

# Perform GridSearchCV to find the best hyperparameters
grid_search = GridSearchCV(model, param_grid, cv=3, scoring='precision_weighted', n_jobs=-1)
grid_search.fit(X_train, y_train)

# Best model from grid search
best_model = grid_search.best_estimator_

# Number of iterations to refine the model
n_iterations = 5

for iteration in range(n_iterations):
    # Train the model
    best_model.fit(X_train, y_train)

    # Make predictions
    y_pred = best_model.predict(X_test)

    # Evaluate the model
    print(f"Iteration {iteration + 1}:")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    # Calculate and print accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}\n")

    # Identify misclassified samples
    misclassified_indices = [i for i in range(len(y_test)) if y_pred[i] != y_test.iloc[i]]

    # If there are no misclassified samples, break the loop
    if not misclassified_indices:
        print("No misclassified samples left. Stopping training.")
        break

    # Get the misclassified samples
    misclassified_X = X_test.iloc[misclassified_indices]
    misclassified_y = y_test.iloc[misclassified_indices]

    # Append misclassified samples to the training set
    X_train = pd.concat([X_train, misclassified_X])
    y_train = pd.concat([y_train, misclassified_y])

# Save the final model to a file
joblib.dump(best_model, 'random_forest_model.pkl')
print("Model saved as 'random_forest_model.pkl'.")

print("Training complete.")

```

```
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# Load the combined dataset
data = pd.read_csv('combined_parsed_data.csv')

# Sample a smaller subset of the data
data = data.sample(frac=0.1, random_state=42)  # Use 10% of the dataset

# Define features and target
feature_columns = data.columns.drop('Source')
X = data[feature_columns]
y = data['Source']

# One-hot encode categorical features
X_encoded = pd.get_dummies(X, drop_first=True)

# Initial split of the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.3, random_state=42)

# Create a Random Forest classifier
model = RandomForestClassifier(random_state=42)

# Adjusted hyperparameter tuning using GridSearchCV
param_grid = {
    'n_estimators': [100],  # Reduced number of estimators
    'max_depth': [None, 10],  # Limited options
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1],
    'max_features': ['sqrt', 'log2']  # Use valid options
}

# Perform GridSearchCV to find the best hyperparameters
grid_search = GridSearchCV(model, param_grid, cv=3, scoring='precision_weighted', n_jobs=-1)
grid_search.fit(X_train, y_train)

# Best model from grid search
best_model = grid_search.best_estimator_

# Number of iterations to refine the model
n_iterations = 5
accuracy_history = []

for iteration in range(n_iterations):
    # Train the model
    best_model.fit(X_train, y_train)

    # Make predictions
    y_pred = best_model.predict(X_test)

    # Evaluate the model
    print(f"Iteration {iteration + 1}:")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    # Calculate and print accuracy
    accuracy = accuracy_score(y_test, y_pred)
    accuracy_history.append(accuracy)
    print(f"Accuracy: {accuracy:.4f}\n")

    # Plotting the confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap='Blues')
    plt.title(f'Confusion Matrix (Iteration {iteration + 1})')
    plt.colorbar()
    tick_marks = range(len(set(y)))
    plt.xticks(tick_marks, set(y), rotation=45)
    plt.yticks(tick_marks, set(y))
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.tight_layout()
    plt.savefig(f'confusion_matrix_iteration_{iteration + 1}.png')
    plt.show()

    # Identify misclassified samples
    misclassified_indices = [i for i in range(len(y_test)) if y_pred[i] != y_test.iloc[i]]

    # If there are no misclassified samples, break the loop
    if not misclassified_indices:
        print("No misclassified samples left. Stopping training.")
        break

    # Get the misclassified samples
    misclassified_X = X_test.iloc[misclassified_indices]
    misclassified_y = y_test.iloc[misclassified_indices]

    # Append misclassified samples to the training set
    X_train = pd.concat([X_train, misclassified_X])
    y_train = pd.concat([y_train, misclassified_y])

# Save the final model to a file
joblib.dump(best_model, 'random_forest_model.pkl')
print("Model saved as 'random_forest_model.pkl'.")

# Plot accuracy history
plt.figure(figsize=(10, 6))
plt.plot(range(1, len(accuracy_history) + 1), accuracy_history, marker='o')
plt.title('Accuracy Over Iterations')
plt.xlabel('Iteration')
plt.ylabel('Accuracy')
plt.xticks(range(1, len(accuracy_history) + 1))
plt.grid()
plt.savefig('accuracy_over_iterations.png')
plt.show()

print("Training complete.")

```

