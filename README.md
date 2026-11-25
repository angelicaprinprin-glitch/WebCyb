# WebCyb – Phishing Email Checker

Paste an email you received and WebCyb tells you if it is phishing, which warning signs it found,
and what to do next.

Everything runs in your browser: the email you paste is never sent anywhere or stored.

## What it checks
- Over 300 phrases scammers use (English and Spanish): urgency, threats, fake security alerts,
  requests for passwords or card numbers, payment and gift-card requests, prizes, inheritance scams,
  fake deliveries, job offers, fake tech support, secrecy, generic greetings and odd wording.
- Links: fake brand links, misspelled brands (paypa1), number addresses, shortened links,
  risky endings (.xyz, .top...), "@" tricks, look-alike letters, insecure http.
- Sender: name says one company but the address is another, company messages from free email
  accounts, Reply-To that goes somewhere else.
- Attachments: risky files and hidden double endings (invoice.pdf.exe).
- Formatting: lots of CAPITALS, exclamation marks, huge money amounts.

## Files
- `index.html` – the page
- `style.css` – design (white, pink, light yellow, cheetah print)
- `cheetah.svg` – cheetah print pattern
- `detector.js` – the phishing detector
- `app.js` – shows the results on the page
