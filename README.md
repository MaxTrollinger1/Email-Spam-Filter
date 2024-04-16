# Email Spam Filter

This project is a simple email spam filter designed to detect basic email spam using signature-based detection, link analysis, and other attributes.

## Features

- **Signature-based Detection**: Utilizes known spam signatures to identify and filter spam emails.
- **Link Analysis**: Analyzes links within emails to determine their legitimacy through valid certificates and relevance to spam detection.
- **Attribute Analysis**: Considers various attributes of emails such as unsubscribe features and content to determine spam likelihood.

## How It Works

1. **Signature Matching**: The filter compares incoming emails against a database of known spam signatures. If a match is found, the email is flagged as spam.
2. **Link Analysis**: URLs within emails are analyzed to check for valid ssl certificates. Emails containing such links are marked as spam.

## Usage

1. Import eml files into the emails folder and run the script.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Created By Max Trollinger and Hunter Uebelacker
