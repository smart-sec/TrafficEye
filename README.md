[中文介绍说明](https://github.com/CuriousLearnerDev/TrafficEye/blob/master/README_CN.md)


## 🔧 TrafficEye — Network Traffic Analysis & Security Detection Tool

------

### 📣 Issue Feedback Group

![Issue Feedback](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/2025-06-03_11-45.png)

------

### 📥 Download Links

- **GitHub Release**: 👉 [https://github.com/CuriousLearnerDev/TrafficEye/releases)](https://github.com/CuriousLearnerDev/TrafficEye/releases)
- **Quark Drive (Windows x64)** (Code: `BZx8`): 👉 [https://pan.quark.cn/s/8871cf2ea473](https://pan.quark.cn/s/8871cf2ea473)
- **Quark Drive (Linux x64)** (Code: `8udM`): 👉 [https://pan.quark.cn/s/297011afb565](https://pan.quark.cn/s/297011afb565)

------

### 🛠️ How to Use

#### 🔧 Linux Users

> ⚠️ **Dependency Required: `tshark` must be installed**

Install with:

```bash
sudo apt install tshark
```

Run:

```bash
unzip linux_amd_x64_0.0.8.9.zip
cd linux_amd_x64_0.0.8.9
chmod +x trafficeye
./trafficeye
```

------

#### 🖱️ Windows Users

> ✅ `tshark` is already integrated, no need to install separately.

Run:

```text
Double-click to launch the main executable.
```

------

### 📄 Security Detection Rules

#### Rule Syntax

Security detection rules are defined under the `safety_testing` section in the `config.yaml` file.

| Identifier                    | Description                             |
| ----------------------------- | --------------------------------------- |
| `ALL`                         | Match all fields                        |
| `!xxx`                        | Exclude field `xxx` from detection      |
| `URI`                         | Complete URL                            |
| `URI_key`                     | Key names in the URL query              |
| `URI_value`                   | Values in the URL query                 |
| `ALL_headers`                 | All HTTP headers                        |
| `headers:xxx`                 | Specific header, e.g., `headers:cookie` |
| `binary`                      | Raw binary content                      |
| `forms_body`                  | Whole form content                      |
| `forms_key_body`              | Key names in form data                  |
| `forms_value_body`            | Values in form data                     |
| `json_body`                   | Entire JSON body                        |
| `json_key_body`               | JSON key names                          |
| `json_value_body`             | JSON values                             |
| `json_item_body`              | JSON list items                         |
| `xml_body`                    | Whole XML content                       |
| `xml_value_body`              | XML node values                         |
| `xml_attribute_body`          | XML attribute values                    |
| `multipart_body`              | Entire multipart content                |
| `multipart_file_name_body`    | Uploaded file names                     |
| `multipart_content_type_body` | Uploaded file MIME types                |
| `multipart_data_body`         | Binary content of uploaded files        |

#### Example Rule

```yaml
safety_testing:
  Directory_Traversal_Attack:
    name:
      - "Directory traversal payload using (/../) or (/.../)"
    detection_location:
      - 'URI|forms_key_body|multipart_file_name_body|ALL_headers|xml_value_body|!headers:referer'
    rules:
      - >-
        (?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])
    severity:
      - Medium
```
For example
```yaml
safety_testing:
  Directory_Traversal_Attack:
    name:
      - "Directory traversal payload using (/../) or (/.../)"
    detection_location:
      - 'URI|forms_key_body|multipart_file_name_body|ALL_headers|xml_value_body|!headers:referer'
    rules:
      - >-
        (?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])
    severity:
      - Medium
```

This rule will detect directory traversal in the following fields:

1. **`URI`**
    → The entire URL string, e.g.:

   ```
   http://example.com/download.php?file=../../etc/passwd
   ```

2. **`forms_key_body`**
    → The key name in a form submission, e.g.:

   ```
   username=admin&file=../../../etc/shadow
   ↑ This is detected in forms_key_body
   ```

3. **`multipart_file_name_body`**
    → The filename field during file uploads, e.g.:

   ```
   Content-Disposition: form-data; name="upload"; filename="../../shell.php"
   ```

4. **`ALL_headers`**
    → All HTTP headers, such as `User-Agent`, `Cookie`, `X-Forwarded-For`, etc.

5. **`xml_value_body`**
    → The value of a node in XML content, e.g.:

   ```
   <config>../../etc/passwd</config>
   ```

6. **`!headers:referer`**
    → Excludes detection in the `Referer` HTTP header.

------

### 📅 Development Progress

- > **Note:** The source code is no longer publicly available after version 0.0.7.

  - **2025-07-10**：Add geoip2IP query
  
  - **2025-07-09**: Beautification generation Report
  - **2025-07-08**: Add English display
  - **2025-06-07**: Security detection rule writing completed
  - **2025-05-25**: Added detailed rule matching display, including rule, severity level, match location, and risk highlight
  - **2025-05-24**: Introduced risk analysis module
  - **2025-05-10**: Performance optimization: separated data and view, avoided repeated icon loading, reduced GUI overhead, and made models lazy-loaded
  - **2025-05-03**: Added statistics for IP access to URIs
  - **2025-05-02**: Real-time interactive experience for log analysis (dynamic updates)
  - **2025-05-01**: Fixed display bugs, improved multi-core processing for large LOG file analysis
  - **2025-04-28**: Optimized memory usage for large traffic file analysis; auto-write to disk when output exceeds 200,000 lines
  - **2025-04-28**: Performance testing completed — WEB log module can handle 2GB files and 4 million entries
  - **2025-04-26**: By default, AI detection and binary traffic identification are disabled to improve speed
  - **2025-04-24**: Further performance tuning
  - **2025-04-23**: Statistical analysis charts now support full-screen view
  - **2025-04-20**: Optimized traffic parsing speed and GUI; added AI analysis for URI, headers, and body content
  - **2025-04-19**: Improved basic AI threat detection module
  - **2025-04-18**: Began development of threat intelligence module
  - **2025-04-17**: Started working on AI analysis engine
  - **2025-04-15**: Added TLS decryption support
  - **2025-04-14**: GUI optimization and feature refinement
  - **2025-04-13**: Introduced binary file extraction functionality
  - **2025-04-12**: Started development of binary extraction module
  - **2025-04-11**: Began GUI modifications
  - **2025-04-10**: Started writing detection regex patterns
  - **2025-04-10**: Refactored core processing logic
  - **2025-04-09**: Initiated log extraction module
  - **2025-04-08**: Started working on regex patterns for log parsing
  - **2025-04-06**: Session replay module development begins
  - **2025-04-05**: Designed structured output stream logic
  
  And more under continuous development...

------

### 🧪 Tool Overview

**TrafficEye** is a modular traffic analysis and threat detection tool tailored for blue team operations, penetration testing, and network defense. It helps uncover web-based threats (e.g., SQLi, XSS, Webshells) and supports extensive customization and automation.

------

### 🧱 Architecture Overview

![Architecture](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/2025-04-04_22-37.png)

------

### 🚀 Key Features

#### ✅ Packet Capture Analysis

- Supports `.pcapng` files
- HTTP data extraction for Burp Suite
- POST data in text and hex
- Filtered URI & HTTP payload output

#### 📄 Log File Analysis

- Apache, Nginx, JSON, F5, HAProxy, Tomcat, IIS

#### 🔁 Traffic Replay

- Raw request replay
- Binary request replay
- Session-based replay (e.g., Godzilla multi-request WebShell sessions)

#### 📦 Binary Extraction

- Java, C# serialized data
- ZIP, 7z, RAR, TAR, GZ
- Images (JPG, PNG, etc.)
- Audio/Video (MP3, MP4, etc.)
- Scripts, documents, emails, databases

#### 📊 Statistics

- URI, IP, methods, frequency
- GeoIP resolution

#### 🧰 Security Detection

- Info leak
- Directory traversal
- LFI/RFI
- RCE
- SQL injection
- XSS

#### 🧠 AI-based Detection

- URI/body/header focused analysis
- Automated batch threat analysis

------

### 📸 GUI Preview

- Dashboard stats

  ![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250709173550361.png)

- Binary Extraction

  ![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250425105119351.png)

- statistical analysis

  ![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250710131738835.png)

  ![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250710132004867.png)

  ![image-20250710132043074](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250710132043074.png)

- Log Analysis

  ![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20250710132135112.png)

------

### 📁 Code Structure Overview

- `main.py`: Entry point
- `core_processing.py`: HTTP parsing engine
- `binary_extraction.py`: Binary extraction logic
- `log_parsing/`: Log format identification and parsers
- `replay_request.py`: Traffic replay
- `url_statistics.py`: URI & IP statistics
- `history/`: Persistent scan results
- `lib/`: IP location, CLI, icons, etc.
- `modsec/`: OWASP ModSecurity rule integration
- `config.yaml`: All customizable rules & settings

------

### 🙏 Special Thanks

- Zhigong Shanfang Lab
- SnowBaby
- ChinaRan404
- TangTang
- niuᴗu
- SnowBaby
- Woshuwacao

------

### 🧠 Future Plans

- ✅ Log alerting system
- ✅ Threat Intelligence API integration (VT, CriminalIP, AbuseIPDB)
- ✅ ModSecurity rule simulation
- ✅ WebShell detection (Godzilla, Behinder, AntSword, etc.)

------

### 📬 Author's Official WeChat

![img](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/qrcode_for_gh_e911bdfdbe01_344.png)
