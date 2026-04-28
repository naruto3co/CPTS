# Other Upload Attacks (Regenerated)

## 1. Filename Injection
- Command Injection
- XSS
- SQL Injection

### Example
```bash
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
```

---

## 2. Upload Directory Disclosure
Techniques:
- Upload duplicate filename
- Send parallel requests
- Use extremely long filenames

Potential result:
```bash
Cannot write to C:\xampp\htdocs\uploads\
```

---

## 3. Windows-Specific Attacks

### Reserved Characters
```text
| < > * ?
```

### Reserved Names
```text
CON
COM1
LPT1
NUL
```

---

## 4. Windows 8.3 Abuse

Real file:
```text
hackthebox.txt
```

Short form:
```text
HAC~1.TXT
```

Potential overwrite target:
```text
web.config
```

---

## 5. Advanced File Processing Exploits
Examples:
- FFmpeg XXE
- ImageMagick RCE
- Metadata parser bugs
- File conversion bugs

---

## Attack Flow

```text
Upload
 ├── Filename Injection
 ├── Path Disclosure
 ├── Windows Abuse
 └── File Processing Exploit
```

---

## Pentest Checklist

- Extension bypass
- MIME bypass
- Magic bytes bypass
- Filename injection
- Path disclosure
- Windows edge cases
- Library exploitation
