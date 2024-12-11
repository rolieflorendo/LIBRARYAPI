<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';

session_start(); // Start a session to store tokens

$app = new \Slim\App;

// Generate and store token in session
function generateToken($data, $expire = 600) {
    $key = 'secretkey';
    $payload = [
        'iss' => 'http://security.org',
        'aud' => 'http://security.com',
        'iat' => time(),
        'exp' => time() + $expire,
        'data' => $data
    ];

    $jwt = JWT::encode($payload, $key, 'HS256');
    $_SESSION['token'] = $jwt; // Store token in session
    return $jwt;
}

// Validate and consume token
function validateAndConsumeToken($jwt) {
    $key = 'secretkey';
    if (!isset($_SESSION['token']) || $_SESSION['token'] !== $jwt) {
        return false; // Invalid token
    }

    try {
        JWT::decode($jwt, new Key($key, 'HS256'));
        unset($_SESSION['token']); // Expire token after successful use
        return true;
    } catch (Exception $e) {
        return false; // Token invalid or expired
    }
}

// Database configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
$app->post('/user/register', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check if username already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :uname");
        $stmt->execute([':uname' => $uname]);
        if ($stmt->fetch()) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Username already exists"]]));
            return $response;
        }

        // Insert new user
        $sql = "INSERT INTO users (username, password) VALUES (:uname, :pass)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':uname' => $uname,
            ':pass' => hash('SHA256', $pass)
        ]);
        $response->getBody()->write(json_encode(["status" => "success", "data" => null]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});

$app->post('/user/auth', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Verify credentials
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :uname AND password = :pass");
        $stmt->execute([
            ':uname' => $uname,
            ':pass' => hash('SHA256', $pass)
        ]);

        if ($stmt->fetch()) {
            $jwt = generateToken(["name" => $uname]);
            $_SESSION['auth_token'] = $jwt; // Store the authentication token in the session
            $response->getBody()->write(json_encode(["status" => "success", "data" => ["token" => $jwt]]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Authentication failed"]]));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});

$app->post('/user/show', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    // Validate the authentication token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(401)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid or unauthorized token"]]));
    }

    // Decode the JWT to get the username
    try {
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name; // Use a different variable name to avoid confusion

        // Ensure the correct database credentials are being used
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Retrieve employee details from the database
        $stmt = $conn->prepare("SELECT username, password FROM users WHERE username = :username");
        $stmt->execute([':username' => $usernameFromToken]); // Use the decoded username here

        $employee = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($employee) {
            $response->getBody()->write(json_encode(["status" => "success", "data" => $employee]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Employee not found"]]));
        }
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    }

    return $response;
});

$app->post('/user/update', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if token, new username, and password are provided
    if (!isset($data->token, $data->new_username, $data->new_password)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token, new username, and new password are required"]]));
    }

    $jwt = $data->token;
    $newUsername = $data->new_username;
    $newPassword = $data->new_password;

    try {
        // Validate the authentication token
        if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
            return $response->withStatus(401)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid or unauthorized token"]]));
        }

        // Decode the JWT to get the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Ensure the correct database credentials are being used
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update the user's username and password
        $stmt = $conn->prepare("UPDATE users SET username = :new_username, password = :new_password WHERE username = :current_username");
        $updated = $stmt->execute([
            ':new_username' => $newUsername,
            ':new_password' => hash('SHA256', $newPassword), // Hash the password for security
            ':current_username' => $usernameFromToken
        ]);

        if ($updated) {
            $response->getBody()->write(json_encode(["status" => "success", "data" => ["title" => "User updated successfully"]]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Failed to update user"]]));
        }
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});

$app->post('/user/delete', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    try {
        // Validate the authentication token
        if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
            return $response->withStatus(401)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid or unauthorized token"]]));
        }

        // Decode the JWT to get the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Ensure the correct database credentials are being used
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete the user's account
        $stmt = $conn->prepare("DELETE FROM users WHERE username = :username");
        $deleted = $stmt->execute([':username' => $usernameFromToken]);

        if ($deleted) {
            // Clear the session token upon successful deletion
            unset($_SESSION['auth_token']);
            $response->getBody()->write(json_encode(["status" => "success", "data" => ["title" => "User account deleted successfully"]]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Failed to delete user account"]]));
        }
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$app->post('/author/register', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check if username already exists
        $stmt = $conn->prepare("SELECT * FROM authors WHERE username = :uname");
        $stmt->execute([':uname' => $uname]);
        if ($stmt->fetch()) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Author name already exists"]]));
            return $response;
        }

        // Insert new author without specifying authorid (assuming it's auto-incremented)
        $sql = "INSERT INTO authors (username, password) VALUES (:uname, :pass)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':uname' => $uname,
            ':pass' => hash('SHA256', $pass)
        ]);

        $response->getBody()->write(json_encode(["status" => "Author Registered Successfully", "data" => null]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});

$app->post('/author/auth', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Verify credentials
        $stmt = $conn->prepare("SELECT * FROM authors WHERE username = :uname AND password = :pass");
        $stmt->execute([
            ':uname' => $uname,
            ':pass' => hash('SHA256', $pass)
        ]);

        if ($stmt->fetch()) {
            $jwt = generateToken(["name" => $uname]);
            $_SESSION['auth_token'] = $jwt; // Store the authentication token in the session
            $response->getBody()->write(json_encode(["status" => "Author Authenticated", "data" => ["token" => $jwt]]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Author Authentication failed"]]));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    $conn = null;
    return $response;
});

$app->post('/author/post', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    // Check if the provided token matches the one stored in the session
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    // Validate and consume the token
    if (validateAndConsumeToken($jwt)) {
        // Decode the JWT to get the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name; // Use the decoded username

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Fetch the author's authorid using the username from the token
            $stmt = $conn->prepare("SELECT authorid FROM authors WHERE username = :uname");
            $stmt->execute([':uname' => $usernameFromToken]);
            $author = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$author) {
                return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Author not found"]]));
            }

            $authorid = $author['authorid'];
            $bookTitle = $data->title;

            // Validate book title
            if (empty($bookTitle)) {
                return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Book title is required"]]));
            }

            // Insert the book into the database
            $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->execute([
                ':title' => $bookTitle,
                ':authorid' => $authorid
            ]);

            $response->getBody()->write(json_encode(["status" => "success", "data" => ["message" => "Book posted successfully"]]));

        } catch (PDOException $e) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Database error: " . $e->getMessage()]]));
        }

    } else {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid or expired token"]]));
    }

    return $response;
});

$app->post('/author/show', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    try {
        // Decode the token to extract the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all authors from the database
        $stmt = $conn->prepare("SELECT authorid, username FROM authors");
        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($authors) {
            $response->getBody()->write(json_encode(["status" => "success", "data" => $authors]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "No authors found"]]));
        }

    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    }

    return $response;
});

$app->delete('/author/delete', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    try {
        // Decode the token to extract the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the author ID using the username from the token
        $stmt = $conn->prepare("SELECT authorid FROM authors WHERE username = :uname");
        $stmt->execute([':uname' => $usernameFromToken]);
        $author = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Author not found"]]));
        }

        $authorid = $author['authorid'];

        // Delete the author's associated books
        $stmt = $conn->prepare("DELETE FROM books WHERE authorid = :authorid");
        $stmt->execute([':authorid' => $authorid]);

        // Delete the author
        $stmt = $conn->prepare("DELETE FROM authors WHERE authorid = :authorid");
        $stmt->execute([':authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["title" => "Author and associated books deleted successfully"]]));

    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    return $response;
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$app->post('/book/show', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the token is provided
    if (!isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Token is required"]]));
    }

    $jwt = $data->token;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    try {
        // Decode the token to extract the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the author ID using the username from the token
        $stmt = $conn->prepare("SELECT authorid FROM authors WHERE username = :uname");
        $stmt->execute([':uname' => $usernameFromToken]);
        $author = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Author not found"]]));
        }

        $authorid = $author['authorid'];

        // Retrieve the books posted by the author with bookid
        $stmt = $conn->prepare("SELECT bookid, title FROM books WHERE authorid = :authorid");
        $stmt->execute([':authorid' => $authorid]);
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            $response->getBody()->write(json_encode(["status" => "success", "data" => $books]));
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "No books found for this author"]]));
        }

    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    }

    return $response;
});

$app->put('/book/update', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the book ID, title, and token are provided
    if (!isset($data->bookid) || !isset($data->title) || !isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Book ID, title, and token are required"]]));
    }

    $bookid = $data->bookid;
    $title = $data->title;
    $jwt = $data->token;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    try {
        // Decode the token to extract the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the author ID using the username from the token
        $stmt = $conn->prepare("SELECT authorid FROM authors WHERE username = :uname");
        $stmt->execute([':uname' => $usernameFromToken]);
        $author = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Author not found"]]));
        }

        $authorid = $author['authorid'];

        // Check if the book exists and is owned by the author
        $stmt = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->execute([':bookid' => $bookid, ':authorid' => $authorid]);
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Book not found or you do not have permission to update this book"]]));
        }

        // Update the book title
        $stmt = $conn->prepare("UPDATE books SET title = :title WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->execute([':title' => $title, ':bookid' => $bookid, ':authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["title" => "Book title updated successfully"]]));

    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    return $response;
});

$app->delete('/book/delete', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    $data = json_decode($request->getBody());

    // Check if the bookid and token are provided
    if (!isset($data->bookid) || !isset($data->token)) {
        return $response->withStatus(400)->write(json_encode(["status" => "fail", "data" => ["title" => "Book ID and Token are required"]]));
    }

    $bookid = $data->bookid;
    $jwt = $data->token;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid token, access denied"]]));
    }

    try {
        // Decode the token to extract the username
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));
        $usernameFromToken = $decoded->data->name;

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the author ID using the username from the token
        $stmt = $conn->prepare("SELECT authorid FROM authors WHERE username = :uname");
        $stmt->execute([':uname' => $usernameFromToken]);
        $author = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Author not found"]]));
        }

        $authorid = $author['authorid'];

        // Check if the book exists and is owned by the author
        $stmt = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->execute([':bookid' => $bookid, ':authorid' => $authorid]);
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            return $response->withStatus(404)->write(json_encode(["status" => "fail", "data" => ["title" => "Book not found or you do not have permission to delete this book"]]));
        }

        // Delete the book
        $stmt = $conn->prepare("DELETE FROM books WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->execute([':bookid' => $bookid, ':authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["title" => "Book deleted successfully"]]));

    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Token invalid or expired"]]));
    }

    return $response;
});

$app->post('/book/author/view', function (Request $request, Response $response, array $args) use ($servername, $username, $password, $dbname) {
    // Get the raw POST data
    $data = json_decode($request->getBody());

    // Check if the token, authorid, and bookid are provided
    if (!isset($data->token) || !isset($data->authorid) || !isset($data->bookid)) {
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json')->write(json_encode([
            "status" => "fail",
            "message" => "Missing token, authorid, or bookid"
        ]));
    }

    $jwt = $data->token;
    $author_id = $data->authorid;
    $book_id = $data->bookid;

    // Validate the token against the session-stored token
    if (!isset($_SESSION['auth_token']) || $_SESSION['auth_token'] !== $jwt) {
        return $response->withStatus(403)->withHeader('Content-Type', 'application/json')->write(json_encode([
            "status" => "fail",
            "message" => "Invalid token, access denied"
        ]));
    }

    try {
        // Decode the token to extract user data (if necessary)
        $decoded = JWT::decode($jwt, new Key('secretkey', 'HS256'));

        // Connect to the database
        $pdo = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch author information
        $query_author = "SELECT * FROM authors WHERE authorid = :authorid";
        $stmt_author = $pdo->prepare($query_author);
        $stmt_author->bindParam(':authorid', $author_id);
        $stmt_author->execute();
        $author = $stmt_author->fetch(PDO::FETCH_ASSOC);

        // Fetch book information
        $query_book = "SELECT * FROM books WHERE bookid = :bookid";
        $stmt_book = $pdo->prepare($query_book);
        $stmt_book->bindParam(':bookid', $book_id);
        $stmt_book->execute();
        $book = $stmt_book->fetch(PDO::FETCH_ASSOC);

        // Check if both author and book are found
        if ($author && $book) {
            $response_data = [
                "status" => "success",
                "data" => [
                    "author" => [
                        "id" => $author['authorid'],
                        "username" => $author['username']
                    ],
                    "book" => [
                        "id" => $book['bookid'],
                        "title" => $book['title']
                    ]
                ]
            ];
            return $response->withStatus(200)->withHeader('Content-Type', 'application/json')->write(json_encode($response_data));
        } else {
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json')->write(json_encode([
                "status" => "fail",
                "message" => "Author or Book not found"
            ]));
        }
    } catch (Exception $e) {
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json')->write(json_encode([
            "status" => "fail",
            "message" => "Connection failed: " . $e->getMessage()
        ]));
    }
});          


$app->run();
?>