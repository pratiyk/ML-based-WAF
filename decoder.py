import urllib.parse

def decode_url_encoded_data(encoded_str):
    """
    Decode URL encoded string to a readable format.
    
    Args:
        encoded_str (str): The URL encoded string.
        
    Returns:
        str: The decoded string.
    """
    decoded_str = urllib.parse.unquote(encoded_str)
    return decoded_str

# Example usage:
encoded_data = "username%3Djohn%26password%3Dsecret%26submit%3DLogin"
decoded_data = decode_url_encoded_data(encoded_data)
print("Decoded Data:", decoded_data)
