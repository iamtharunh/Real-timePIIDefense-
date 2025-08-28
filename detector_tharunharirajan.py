#!/usr/bin/env python3
import sys, json, csv, re
from pathlib import Path

phoneKeys = {'phone','contact','mobile','alt_phone','alt_contact'}
aadharKeys = {'aadhar','aadhaar'}
passportKeys = {'passport'}
upiKeys = {'upi_id','upi','vpa'}
upiHandles = {
    'upi','ybl','ibl','paytm','okhdfcbank','okaxis','oksbi','okicici',
    'axisbank','hdfcbank','sbi','icici','fbl','airtel','apl','yapl','kbl','axl'
}

def is10DigitPhone(val: str) -> bool:
    digits = re.sub(r'\D', '', val or '')
    return len(digits) == 10

def isAadhar(val: str) -> bool:
    digits = re.sub(r'\D', '', val or '')
    return len(digits) == 12

def isPassport(val: str) -> bool:
    # Common Indian passport format: 1 letter followed by 7 or 8 digits
    return bool(re.fullmatch(r'[A-Za-z]\d{7,8}', (val or '').strip()))

def isUpi(val: str) -> bool:
    v = (val or '').strip()
    if '@' not in v:
        return False
    parts = v.split('@',1)
    if len(parts) != 2:
        return False
    user, handle = parts
    if not re.fullmatch(r'[A-Za-z0-9.\-_]{2,}', user):
        return False
    base = handle.split('.')[0].lower()
    return base in upiHandles

def maskPhone(val: str) -> str:
    digits = re.sub(r'\D', '', val or '')
    if len(digits) != 10:
        return '[REDACTED_PII]'
    return f'{digits[:2]}' + 'X'*6 + f'{digits[-2:]}'

def maskAadhar(val: str) -> str:
    digits = re.sub(r'\D', '', val or '')
    if len(digits) != 12:
        return '[REDACTED_PII]'
    return 'XXXX XXXX ' + digits[-4:]

def maskPassport(val: str) -> str:
    v = (val or '').strip()
    if not isPassport(v):
        return '[REDACTED_PII]'
    return v[0] + 'X' * (len(v)-1)

def maskUpi(val: str) -> str:
    v = (val or '').strip()
    if '@' not in v:
        return '[REDACTED_PII]'
    user, handle = v.split('@',1)
    if len(user) <= 4:
        maskedUser = user[0:1] + 'X'*(max(len(user)-1,0))
    else:
        maskedUser = user[:2] + 'X'*(len(user)-4) + user[-2:]
    return maskedUser + '@' + handle

def maskName(val: str) -> str:
    parts = re.split(r'\s+', (val or '').strip())
    masked = []
    for p in parts:
        if not p:
            continue
        masked.append(p[0] + 'X'*(len(p)-1))
    return ' '.join(masked) if masked else val

def maskEmail(val: str) -> str:
    v = (val or '').strip()
    if '@' not in v:
        return '[REDACTED_PII]'
    local, domain = v.split('@',1)
    if len(local) <= 2:
        mlocal = local[0:1] + 'X'*(max(len(local)-1,0))
    else:
        mlocal = local[:2] + 'XXX'
    return mlocal + '@' + domain

def looksLikeAddress(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    markers = ['street','st.','road','rd','lane','ln','avenue','ave','block','sector','near','opp','apartment','society','floor']
    if any(m in t for m in markers):
        return True
    if re.search(r'\b\d{6}\b', t):
        return True
    return t.count(',') >= 2 and len(t) >= 10

def loadJsonSafe(raw: str):
    try:
        return json.loads(raw)
    except Exception:
        try:
            fixed = raw.replace("'", '"')
            return json.loads(fixed)
        except Exception:
            return {}

def detectAndRedact(record: dict):
    # Work on a shallow copy
    data = {}
    data.update(record)

    # combinational signals
    hasFullName = False
    hasEmail = False
    hasAddress = False
    hasDeviceOrIp = False

    standaloneHit = False
    redacted = dict(data)

    for key, value in data.items():
        k = (key or '').lower()
        v = value if isinstance(value, str) else (json.dumps(value) if value is not None else '')

        # Standalone PII checks
        if k in phoneKeys and is10DigitPhone(v):
            standaloneHit = True
            redacted[key] = maskPhone(v)
            continue
        if k in aadharKeys and isAadhar(v):
            standaloneHit = True
            redacted[key] = maskAadhar(v)
            continue
        if k in passportKeys and isPassport(v):
            standaloneHit = True
            redacted[key] = maskPassport(v)
            continue
        if (k in upiKeys and isUpi(v)):
            standaloneHit = True
            redacted[key] = maskUpi(v)
            continue

        # Combinational signals (note: names of JSON fields are left as-is)
        if k == 'name' and isinstance(v, str) and len(v.split()) >= 2:
            hasFullName = True
        if k == 'email' and isinstance(v, str) and '@' in v:
            hasEmail = True
        if k == 'address' and looksLikeAddress(v):
            hasAddress = True
        # device and ip fields in dataset commonly use underscores; keep them in string checks
        if k in {'ip_address', 'device_id'} and v and v != '0.0.0.0':
            hasDeviceOrIp = True

    comboHits = sum([hasFullName, hasEmail, hasAddress, hasDeviceOrIp])
    isComboPii = comboHits >= 2

    if isComboPii:
        if 'name' in data and isinstance(data['name'], str) and len(data['name'].split()) >= 2:
            redacted['name'] = maskName(data['name'])
        if 'email' in data and isinstance(data['email'], str) and '@' in data['email']:
            redacted['email'] = maskEmail(data['email'])
        if 'address' in data and looksLikeAddress(data.get('address','')):
            redacted['address'] = '[REDACTED_PII]'
        if 'ip_address' in data and data.get('ip_address'):
            redacted['ip_address'] = '[REDACTED_PII]'
        if 'device_id' in data and data.get('device_id'):
            redacted['device_id'] = '[REDACTED_PII]'

    is_pii = bool(standaloneHit or isComboPii)
    return redacted, is_pii

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_tharunharirajan.py iscp_pii_dataset.csv")
        sys.exit(1)
    inPath = Path(sys.argv[1])
    outPath = Path('redacted_output_tharunharirajan.csv')

    with inPath.open('r', newline='', encoding='utf-8') as inf, outPath.open('w', newline='', encoding='utf-8') as outf:
        reader = csv.DictReader(inf)
        fieldnames = ['record_id','redacted_data_json','is_pii']
        writer = csv.DictWriter(outf, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get('record_id')
            rawJson = row.get('Data_json','') or row.get('data_json','')
            data = loadJsonSafe(rawJson)
            if not isinstance(data, dict):
                data = {}
            redactedDict, isPii = detectAndRedact(data)
            redactedJsonStr = json.dumps(redactedDict, ensure_ascii=False)
            writer.writerow({
                'record_id': rid,
                'redacted_data_json': redactedJsonStr,
                'is_pii': str(bool(isPii))
            })

    print(f"Written: {outPath.resolve()}")

if __name__ == '__main__':
    main()

