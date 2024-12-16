# ft_otp.py

**ft_otp.py** is a python script allowing you to create a time based code with a graphical qrcode using the TOTP algorithm. The script will take a hexadecimal key stored in a file and will encrypt it using RSA.

## Usage

```bash
python3 ft_otp.py -h
```

### Command-line Arguments

```bash
options:
  -h, --help  show this help message and exit
  -g G        path to hexadecimal key
  -k K        path to key file to generate a new temporary password
```

### Features

    Generate a TOTP code using an hexadecimal key

### Setup Instructions

    Clone the repository
    Configure the enviorment:
```bash
python -m venv venv
bin source venv/bin/activate
pip install -r requirements.txt
echo "<hexadecimal key>" > key.txt
```
    Run the script:
python3 ft_otp.py key.txt
```

