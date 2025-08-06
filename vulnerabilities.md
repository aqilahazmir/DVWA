# DVWA Vulnerabilities Analysis

This document lists 5 obvious vulnerabilities identified by reading the DVWA source code.  
Each vulnerability is categorized with a type, explanation, and file location in the repository.

---

## 1. SQL Injection
**File:** [vulnerabilities/sqli/source/low.php](https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/low.php)

**Code Snippet:**  
```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );
```

**Why:**
- ```php$id``` is taken directly from user input without sanitization.
- An attacker can inject malicious SQL (e.g., ```php1' OR '1'='1```) to bypass authentication or extract data.


## 2. Stored Cross-Site Scripting (XSS)
**File:** [vulnerabilities/xss_s/source/low.php](https://github.com/digininja/DVWA/blob/master/vulnerabilities/xss_s/source/low.php)

**Code Snippet**
```php
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $insert = "INSERT INTO guestbook (comment) VALUES ( '$message' );";
    mysqli_query($GLOBALS["___mysqli_ston"],  $insert );
}
```

**Why:**
- User input is stored in the database and displayed without HTML escaping.
- Attackers can store scripts like ```php<script>alert('XSS')</script>```. 


## 3. Command Injection
**File:** [vulnerabilities/exec/source/low.php](https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/low.php)

**Code Snippet**
```php
$target = $_REQUEST[ 'ip' ];
$cmd = shell_exec( 'ping -c 3 ' . $target );
```

**Why:**
- User input is directly concatenated into a shell command.
- An attacker can execute arbitrary commands using ```php;``` or ```php&&```.


## 4. Local File Inclusion (LFI)
**File:** [vulnerabilities/fi/source/low.php](https://github.com/digininja/DVWA/blob/master/vulnerabilities/fi/source/low.php)

**Code Snippet**
```php
$file = $_GET['page'];
include($file);
```

**Why:**
- Unsanitized file path from user input can include system files.
- Example: ```php?page=/etc/passwd``` could expose sensitive data.


## 5. Insecure File Upload
**File:** [vulnerabilities/upload/source/low.php](https://github.com/digininja/DVWA/blob/master/vulnerabilities/upload/source/low.php)

**Code Snippet**
```php
$target_path = "uploads/" . basename($_FILES['uploaded']['name']);
move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path);
```
**Why:**
- No file extension or type validation.
- Attacker can upload a ```php.php``` web shell and execute commands remotely.
