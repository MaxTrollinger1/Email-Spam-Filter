# Max Trollinger and Hunter Uebelacker Class Project
# Spam Filter designed to detect basic email spam using signature based detection, link analysis and other attributes
#
#

import hashlib
import os
import email
import requests
from urllib.parse import urlparse
import ssl
import re
from html import unescape
from urlextract import URLExtract

classification_reason = 'None'

# extract email content from eml
def read_email_from_eml(filename):
    with open(filename, 'rb') as file:
        msg = email.message_from_binary_file(file)
        email_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    email_content += part.get_payload()
        else:
            email_content = msg.get_payload()
    return email_content

# Generate sha256 hash of email
# hash generated to check against known hashes
def hash_signature(email_content):
    email_bytes = email_content.encode('utf-8')
    hash_object = hashlib.sha256()
    hash_object.update(email_bytes)
    
    signature = hash_object.hexdigest()
    return signature

# read already known signatures from file
def read_spam_signatures(filename):
    with open(filename, 'r') as file:
        spam_signatures = {line.strip() for line in file}
    return spam_signatures

def has_unsubscribe(email_content):
    return 'unsubscribe' in email_content.lower()

def has_valid_ssl_certificate(url):
    try:
        domain = urlparse(url).netloc
        cert = ssl.get_server_certificate((domain, 443))
        x509 = ssl.PEM_cert_to_DER_cert(cert)
        return True
    except Exception as e:
        print(url)
        return False

def analyze_links(email_content):
    extractor = URLExtract()
    links = extractor.find_urls(email_content)
    return links

def is_spam_email(email_content):
    global classification_reason
    # Check if the email content contains the word "unsubscribe"
    if 'unsubscribe' not in email_content.lower():
        classification_reason = 'No Such Unsubscribe Feature'
        return True
    
    # Analyze links within the email content
    links = analyze_links(email_content)
    # Check each link for SSL certificate
    for link in links:
        if not has_valid_ssl_certificate(link):
            classification_reason = 'No Valid SSL Certificate'
            return True  # If any link lacks proper certification, classify the email as spam
    
    return False

# updates the known signature list
def update_signature_list(email_hash):
    with open(spam_signatures_file, "a") as signature_file:
        signature_file.write("\n" + str(email_hash))
    signature_file.close()

email_directory = "emails"
spam_directory = "spam_emails"
spam_signatures_file = "spam_signatures.txt"

if __name__ == "__main__":

    spam_signatures = read_spam_signatures(spam_signatures_file)

    for filename in os.listdir(email_directory):
        if filename.endswith(".eml"):
            classification_reason = 'Matching Spam Signature'
            filepath = os.path.join(email_directory, filename)
            email_content = read_email_from_eml(filepath)
            signature = hash_signature(email_content)

            # Check if the email is spam based on signature or link analysis
            is_known_signature = signature in spam_signatures
            is_spam = is_known_signature or is_spam_email(email_content)
            
            if is_spam:
                # Move email to spam directory
                spam_filename = os.path.join(spam_directory, filename)
                os.rename(filepath, spam_filename)
                
                if not is_known_signature:
                    # Update signature list if it's a new spam signature
                    print(f"{filename} is spam with unknown signature. Logged signature and moved to {spam_filename} : Reason Of {classification_reason}")
                    update_signature_list(signature)
                else:
                    print(f"{filename} has a matching spam signature, moved to {spam_filename} : Reason Of {classification_reason}")
            else:
                print(f"{filename} is not spam")
