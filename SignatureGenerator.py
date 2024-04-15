import hashlib
import os
import email

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

def hash_signature(email_content):
    email_bytes = email_content.encode('utf-8')
    hash_object = hashlib.sha256()
    hash_object.update(email_bytes)
    signature = hash_object.hexdigest()
    return signature

if __name__ == "__main__":
    spam_directory = "spam_emails"
    spam_signatures_file = "spam_signatures.txt"

    spam_signatures = set()

    for filename in os.listdir(spam_directory):
        if filename.endswith(".eml"):
            filepath = os.path.join(spam_directory, filename)
            email_content = read_email_from_eml(filepath)
            signature = hash_signature(email_content)
            spam_signatures.add(signature)
            
    with open(spam_signatures_file, 'w') as file:
        for signature in spam_signatures:
            file.write(signature + '\n')

    print("Spam signatures have been saved to", spam_signatures_file)
    print("Number of spam signatures saved:", len(spam_signatures))
