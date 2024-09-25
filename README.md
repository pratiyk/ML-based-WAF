# ML-based-WAF
This project implements a machine learning-based Web Application Firewall (WAF) to enhance the security of web applications. The WAF uses advanced algorithms to detect and mitigate various types of web attacks, such as SQL injection, cross-site scripting (XSS), and other malicious requests.

### Classifier
```
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import OneHotEncoder

# Load the combined dataset
data = pd.read_csv('combined_parsed_data.csv')

# Define features and target
feature_columns = data.columns.drop('Source')
X = data[feature_columns]
y = data['Source']

# One-hot encode categorical features
X_encoded = pd.get_dummies(X, drop_first=True)

# Initial split of the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.3, random_state=42)

# Create a Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Number of iterations to refine the model
n_iterations = 5

for iteration in range(n_iterations):
    # Train the model
    model.fit(X_train, y_train)

    # Make predictions
    y_pred = model.predict(X_test)

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

print("Training complete.")
```

### Parser 
```
import re
import csv
from urllib.parse import urlparse, parse_qs

def extract_parameters(param_str):
    """
    Extracts parameters from a URL-encoded string and returns as a formatted string.
    """
    params = parse_qs(param_str)
    return '; '.join([f'{k}={v[0]}' for k, v in params.items()])

def count_special_characters(s):
    """
    Counts occurrences of special characters and patterns commonly associated with attacks.
    """
    # Define patterns associated with attacks
    attack_patterns = {
        'single_quote': r"'",
        'double_quote': r'"',
        'backslash': r'\\',
        'semicolon': r';',
        'double_dash': r'--',
        'asterisk': r'\*',
        'hash': r'#',
        'percent': r'%',
        'ampersand': r'&',
        'pipe': r'\|',
        'question_mark': r'\?',
        'equal_sign': r'=',
        'parentheses': r'\(|\)',
        'angle_brackets': r'<|>',
        'curly_brackets': r'\{|\}',
        'square_brackets': r'\[|\]',
        'dollar_sign': r'\$',
        'at_symbol': r'@',
        'tilde': r'~',
        'backtick': r'`',
        'slash': r'/',
        'colon': r':',
        'exclamation_mark': r'!',
        'javascript_scheme': r'javascript:',
        'eval_function': r'eval\(',
        'alert_function': r'alert\(',
        'file_inclusion': r'file://',
        'path_traversal': r'\.\./',
        'localhost': r'localhost',
        'root_path': r'root'
    }
    
    # Count occurrences of each pattern
    total_count = sum(len(re.findall(pattern, s, re.IGNORECASE)) for pattern in attack_patterns.values())
    
    return total_count

def parse_txt_file(file_in):
    """
    Parses a .txt file and returns a list of log entries.
    """
    with open(file_in, 'r', encoding='utf-8') as fin:
        return fin.readlines()

def parse_file(file_in, file_out):
    # Determine file type
    if file_in.endswith('.txt'):
        lines = parse_txt_file(file_in)
    else:
        raise ValueError("Unsupported file type. Only .txt files are supported.")

    with open(file_out, 'w', newline='', encoding='utf-8') as fout:
        csv_writer = csv.writer(fout)
        # Write the header with multiple method columns
        csv_writer.writerow([
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
            'Full URL', 'URL Path', 'Query Params', 'Query Params Length', 
            'Number of Query Params', 'Body Params', 
            'Content-Length', 'Content-Type', 'User-Agent', 'Host', 
            'Accept', 'Accept-Encoding', 'Accept-Charset', 'Accept-Language', 
            'Pragma', 'Connection', 'Body Length', 'URL Length', 
            'Special Characters Count in URL', 'Special Characters Count in Query Params'
        ])
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            method_col = {
                'GET': 0,
                'POST': 0,
                'PUT': 0,
                'DELETE': 0,
                'PATCH': 0
            }
            
            # Check if the line starts with a valid HTTP method
            if any(line.startswith(method) for method in method_col.keys()):
                # Extract Method
                method = line.split(' ')[0]
                method_col[method] = 1  # Set to 1 if the method is present
                
                # Extract Full URL
                full_url = line.split(' ')[1]
                
                # Extract URL Path
                url_path = urlparse(full_url).path
                
                # Extract Query Parameters
                query_params = parse_qs(urlparse(full_url).query)
                query_params_str = extract_parameters(urlparse(full_url).query)
                query_params_length = len(urlparse(full_url).query)
                num_query_params = len(query_params)
                
                # Count special characters
                url_special_characters_count = count_special_characters(url_path)
                query_special_characters_count = count_special_characters(urlparse(full_url).query)
                
                # Initialize other fields
                content_length = ''
                content_type = ''
                user_agent = ''
                host = ''
                accept = ''
                accept_encoding = ''
                accept_charset = ''
                accept_language = ''
                pragma = ''
                connection = ''
                body_params_str = ''
                
                headers = {}
                body = ''
                
                # Loop through headers and body
                j = 1
                while i + j < len(lines) and not lines[i + j].strip() == '':
                    header_line = lines[i + j].strip()
                    if header_line.startswith('Content-Length:'):
                        content_length = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Content-Type:'):
                        content_type = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('User-Agent:'):
                        user_agent = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Host:'):
                        host = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Accept:'):
                        accept = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Accept-Encoding:'):
                        accept_encoding = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Accept-Charset:'):
                        accept_charset = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Accept-Language:'):
                        accept_language = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Pragma:'):
                        pragma = header_line.split(':', 1)[1].strip()
                    elif header_line.startswith('Connection:'):
                        connection = header_line.split(':', 1)[1].strip()
                    j += 1
                
                # The body is the line after the headers
                if i + j < len(lines):
                    body = lines[i + j].strip()
                    # Extract body parameters (if the body is URL-encoded)
                    body_params_str = extract_parameters(body)
                
                # Calculate lengths for additional features
                body_length = len(body)
                url_length = len(full_url)
                    
                # Append the extracted features to the CSV
                csv_writer.writerow([
                    method_col['GET'], method_col['POST'], method_col['PUT'], 
                    method_col['DELETE'], method_col['PATCH'],
                    full_url, url_path, query_params_str, query_params_length, 
                    num_query_params, body_params_str, 
                    content_length, content_type, user_agent, host, 
                    accept, accept_encoding, accept_charset, accept_language, 
                    pragma, connection, body_length, url_length,
                    url_special_characters_count, query_special_characters_count
                ])
                
                i += j + 1
            else:
                i += 1

# Example usage
# parse_file('input.txt', 'output.csv')

```
