# Max Trollinger Class Project
# Spam Filter designed to detect basic email spam using signature based detection, link analysis and other attributes
#
#

import hashlib
import os
import email

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
            filepath = os.path.join(email_directory, filename)
            email_content = read_email_from_eml(filepath)
            signature = hash_signature(email_content)

            # Check if the signature matches any known spam signatures
            is_known_signature = False
            is_spam = True
            for spam_signature in spam_signatures:
                if signature == spam_signature:
                    is_known_signature = True
                    break

            is_spam = not has_unsubscribe(email_content)
                
            if is_known_signature or is_spam:
                # Move email to spam directory
                spam_filename = os.path.join(spam_directory, filename)
                os.rename(filepath, spam_filename)

                if is_spam and not is_known_signature:
                    # update signature to reflect new spam signature
                    print(f"{filename} is spam with unknown signature. Logged signature and moved to {spam_filename}")
                    update_signature_list(signature)
                elif is_known_signature:
                    print(f"{filename} has a matching spam signature, moved to {spam_filename}")
            else:
                print(f"{filename} is not spam")
