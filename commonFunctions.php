<?php
// Include required module for database functions
require 'module5.php';

// Set session cookie to be accessible only through HTTP (for security)
ini_set("session.cookie_httponly", 1);
session_start(); // Start the session to track user data
header("Content-Type: application/json"); // Set the response type to JSON

// Get the raw POST data as a JSON string and decode it into an associative array
$json_str = file_get_contents('php://input');
$json_obj = json_decode($json_str, true);

// If the login credentials (username and password) are provided, attempt to login
if(isset($json_obj['username']) && isset($json_obj['password'])) {
    login($mysql, (string) $json_obj['username'], (string) $json_obj['password']);
}

// If the user wants to create a new account (createUser and createPass are set), create the user
if(isset($json_obj['createUser']) && isset($json_obj['createPass'])) {
    createUser($mysql, (string) $json_obj['createUser'], (string) $json_obj['createPass']);
}

// If a logout request is received, call the logout function
if(isset($json_obj['logout'])) {
    logout();
}

// If a checkLogin request is made, check if the user is currently logged in
if(isset($json_obj['checkLogin'])) {
    checkLogin();
}

// If event details are provided (name, date, time, token, post), post a new event
if(isset($json_obj['name']) && isset($json_obj['date']) && isset($json_obj['time']) && isset($json_obj['token']) && isset($json_obj['post'])) {
    postEvent($mysql, $json_obj, (string) $json_obj['name'], (string) $json_obj['date'], (string) $json_obj['time'], (string) $json_obj['token']);
}

// If month and year are provided, retrieve events for that month
if(isset($json_obj['month']) && isset($json_obj['year'])) {
    getMonthEvents($mysql, (string) $json_obj['month'], (string) $json_obj['year']);
}

// If the user has provided a token, event ID, and delete flag, attempt to delete the event
if(isset($json_obj['token']) && isset($json_obj['id']) && isset($json_obj['delete'])) {
    deleteEvent($mysql, (string) $json_obj['token'], (int) $json_obj['id']);
}

// If editing an event (name, date, time, token, event ID, and edit flag are provided), update the event
if(isset($json_obj['name']) && isset($json_obj['date']) && isset($json_obj['time']) && isset($json_obj['token']) && isset($json_obj['id']) && isset($json_obj['edit'])) {
    editEvent($mysql, (string) $json_obj['name'], (string) $json_obj['date'], (string) $json_obj['time'], (string) $json_obj['token'], (int) $json_obj['id']);
}

// If sharing the calendar for a specific month and year, get shared events
if(isset($json_obj['shareMonth']) && isset($json_obj['shareYear'])) {
    getShared($mysql, (string) $json_obj['shareMonth'], (string) $json_obj['shareYear']);
}

// If a calendar share request is made with a user and token, share the calendar
if(isset($json_obj['sharee']) && isset($json_obj['token'])) {
    shareCal($mysql, (string) $json_obj['sharee'], (string) $json_obj['token']);
}

// If a request to find all available calendars (cals) is made, fetch and return them
if(isset($json_obj['cals'])) {
    findCalendars($mysql);
}

// If a specific sharer's events are requested (ymonth, yyear, and sharer), get the sharer's events
if(isset($json_obj['ymonth']) && isset($json_obj['yyear']) && isset($json_obj['sharer'])) {
    findSharerEvents($mysql, (string) $json_obj['ymonth'], (string) $json_obj['yyear'], (string) $json_obj['sharer']);
}

// If a specific sharer's shared events are requested (symonth, syyear, and sharer), get the sharer's shared events
if(isset($json_obj['symonth']) && isset($json_obj['syyear']) && isset($json_obj['sharer'])) {
    getSharerShared($mysql, (string) $json_obj['symonth'], (string) $json_obj['syyear'], (string) $json_obj['sharer']);
}

function getSharerShared($mysql, $month, $year, $sharer) {
    // Check if the logged-in user is allowed to see the sharer's shared events by querying the 'share_calendar' table
    $stmt = $mysql->prepare("select sharee from share_calendar where sharer = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the sharer's username to the query and execute it
    $stmt->bind_param('s', $sharer);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Fetch all sharees (users who can view the sharer's shared events)
    $sharees = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    // Extract only the sharee usernames from the result
    $shareeUsernames = array_column($sharees, 'sharee');

    // Check if the logged-in user is one of the sharees
    if (in_array($_SESSION['username'], $shareeUsernames)) {
        // If allowed, prepare a query to fetch the event IDs that the current user has access to
        $stmt = $mysql->prepare("select event_id from shared_events where username = ?");
        if (!$stmt) {
            // If query preparation fails, display an error and return a failure message
            printf("Query Prep Failed: %s\n", $mysql->error);
            echo json_encode(array(
                "success" => false,
                "message" => "Could not update."
            ));
            exit;
        }

        // Bind the logged-in user's username to the query and execute it
        $stmt->bind_param('s', $_SESSION['username']);
        $stmt->execute();
        $result = $stmt->get_result();
        $eventIds = [];

        // Collect the event IDs that the user has access to
        while ($row = $result->fetch_assoc()) {
            $eventIds[] = $row['event_id'];
        }
        $stmt->close();

        // If the user does not have any shared events, return an empty array
        if (empty($eventIds)) {
            echo json_encode(array(
                "success" => true,
                "shared" => []
            ));
            exit;
        }

        // Prepare a query to fetch events from the 'events' table where event IDs match
        $placeholders = str_repeat('?,', count($eventIds) - 1) . '?';
        $stmt = $mysql->prepare("SELECT * FROM events WHERE month(event_date) = ? AND year(event_date) = ? AND id IN ($placeholders)");
        if (!$stmt) {
            // If query preparation fails, display an error and stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Merge the month, year, and event IDs for the query
        $params = array_merge([$month, $year], $eventIds);
        $stmt->bind_param(str_repeat('i', count($params)), ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();

        // If events are found, sanitize and return them in the response
        if ($result->num_rows > 0) {
            $events = $result->fetch_all(MYSQLI_ASSOC);
            $sanEvents = array_map(function($event) {
                return array_map('htmlentities', $event); // Sanitize each event's data to prevent XSS
            }, $events);

            echo json_encode(array(
                "success" => true,
                "shared" => $sanEvents
            ));
        } else {
            // If no events are found, return an empty shared events array
            echo json_encode(array(
                "success" => true,
                "shared" => []
            ));
        }
        exit;
    }
}

function findSharerEvents($mysql, $month, $year, $sharer) {
    // Check if the logged-in user is allowed to see the sharer's events by querying the 'share_calendar' table
    $stmt = $mysql->prepare("SELECT sharee FROM share_calendar WHERE sharer = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the sharer's username to the query and execute it
    $stmt->bind_param('s', $sharer);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Fetch all sharees (users who can view the sharer's events)
    $sharees = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    // Extract only the sharee usernames from the result
    $shareeUsernames = array_column($sharees, 'sharee');

    // Check if the logged-in user is one of the sharees
    if (in_array($_SESSION['username'], $shareeUsernames)) {
        // If allowed, prepare a query to fetch the sharer's events for the specified month and year
        $stmt = $mysql->prepare("select * from events where month(event_date) = ? and year(event_date) = ? and username = ?");
        if (!$stmt) {
            // If query preparation fails, display an error and stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Bind the month, year, and sharer's username to the query and execute it
        $stmt->bind_param('sss', $month, $year, $sharer);
        $stmt->execute();
        $result = $stmt->get_result();
        
        // Fetch all events for the sharer
        $events = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        // Sanitize the event data to prevent XSS
        $sanEvents = array_map(function($event) {
            return array_map('htmlentities', $event); // Sanitize each event's data
        }, $events);

        // Return the events in a JSON response
        echo json_encode(array(
            "success" => true,
            "events" => $sanEvents
        ));
        exit;
    }
    // If the user is not allowed to view the sharer's events, nothing is done (you can add an error response if needed)
}

function findCalendars($mysql) {
    // Prepare SQL query to fetch the list of users who have shared their calendars with the current user (sharee)
    $stmt = $mysql->prepare("select sharer from share_calendar where sharee = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the current user's username (from session) and execute the query
    $stmt->bind_param('s', $_SESSION['username']);
    $stmt->execute();
    $result = $stmt->get_result();

    // Initialize an array to store the sharer's usernames
    $sharers = [];
    while($row = $result->fetch_assoc()) {
        // Add each sharer's username to the array, sanitizing it to prevent XSS
        $sharers[] = htmlentities($row['sharer']);
    }

    $stmt->close();

    // If there are any sharers, return a success response with the list of sharers
    if(!empty($sharers)) {
        echo json_encode(array(
            "success" => true,
            "sharers" => $sharers
        ));
    } else {
        // If no sharers are found, return a failure response
        echo json_encode(array(
            "success" => false
        ));
    }
}

function shareCal($mysql, $sharee, $token) {
    // Verify CSRF token to prevent request forgery
    if(!hash_equals($_SESSION['token'], $token)){
        die("Request forgery detected"); // Stop script if tokens don't match
    }

    // Prepare SQL query to check if the 'sharee' (user to share with) exists in the database
    $stmt = $mysql->prepare("select username from users where username = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the 'sharee' username to the query and execute it
    $stmt->bind_param('s', $sharee);
    $stmt->execute();
    
    // If the user exists (fetches a result), proceed to insert the share record
    if($stmt->fetch()) {
        $stmt->close();

        // Prepare SQL query to insert a record into the 'share_calendar' table to link the sharer and sharee
        $stmt = $mysql->prepare("insert into share_calendar (sharer, sharee) values (?, ?)");
        if (!$stmt) {
            // If query preparation fails, display an error and stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Bind the sharer's (logged-in user's) username and the sharee's username to the query and execute it
        $stmt->bind_param('ss', $_SESSION['username'], $sharee);
        $stmt->execute();
        $stmt->close();

        // Return a success response indicating that the calendar was shared
        echo json_encode(array(
            "success" => true
        ));
    } else {
        // If the sharee does not exist, close the statement and exit
        $stmt->close();
        exit;
    }
}

function getShared($mysql, $month, $year) {
    // Prepare SQL query to fetch event IDs for events shared with the current user
    $stmt = $mysql->prepare("select event_id from shared_events where username = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and return a failure response
        printf("Query Prep Failed: %s\n", $mysql->error);
        echo json_encode(array(
            "success" => false,
            "message" => "Could not update."
        ));
        exit;
    }

    // Bind the username and execute the query
    $stmt->bind_param('s', $_SESSION['username']);
    $stmt->execute();
    $result = $stmt->get_result();

    // Collect all the event IDs that are shared with the current user
    $eventIds = [];
    while ($row = $result->fetch_assoc()) {
        $eventIds[] = $row['event_id'];
    }
    $stmt->close();

    // If no events are shared with the current user, return an empty response
    if (empty($eventIds)) {
        echo json_encode(array(
            "success" => true,
            "shared" => []
        ));
        exit;
    }

    // Build the SQL query to retrieve events for the specified month and year
    // The query filters by the event IDs that are shared with the user
    $placeholders = str_repeat('?,', count($eventIds) - 1) . '?';
    $stmt = $mysql->prepare("SELECT * FROM events WHERE month(event_date) = ? AND year(event_date) = ? AND id IN ($placeholders)");
    if (!$stmt) {
        // If query preparation fails, stop execution
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Prepare the parameters for binding: month, year, and the event IDs
    $params = array_merge([$month, $year], $eventIds);
    
    // Bind the parameters dynamically based on the number of event IDs
    $stmt->bind_param(str_repeat('i', count($params)), ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    // Check if there are any events found for the specified month, year, and shared events
    if ($result->num_rows > 0) {
        // If events are found, fetch them and sanitize the output to prevent XSS
        $events = $result->fetch_all(MYSQLI_ASSOC);
        $sanEvents = array_map(function($event) {
            return array_map('htmlentities', $event); // Sanitize each event's data
        }, $events);

        // Return the list of shared events as a success response
        echo json_encode(array(
            "success" => true,
            "shared" => $sanEvents
        ));
    } else {
        // If no events are found, return an empty list of shared events
        echo json_encode(array(
            "success" => true,
            "shared" => []
        ));
    }
    exit; // End the script after returning the response
}

function login($mysql, $username, $password) {
    // Prepare SQL query to get the hashed password for the provided username
    $stmt = $mysql->prepare("select password_hash from users where username = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the username to the query and execute it
    $stmt->bind_param('s', $username);
    $stmt->execute();
    
    // Initialize variable to hold the fetched hashed password
    $realPass = "";
    $stmt->bind_result($realPass);
    
    // Verify the password: if the username exists and the password matches
    if ($stmt->fetch() && password_verify($password, $realPass)) {
        // If login is successful, set session variables
        $stmt->close();
        $_SESSION['username'] = $username; // Store username in session
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32)); // Generate and store a CSRF token
        
        // Return a success response with the CSRF token
        echo json_encode(array(
            "success" => true,
            "token" => htmlentities($_SESSION['token']) // Return the token as part of the response
        ));
        exit;
    } else {
        // If username or password is incorrect, close the statement and return an error message
        $stmt->close();
        echo json_encode(array(
            "success" => false,
            "message" => "Incorrect Username or Password"
        ));
        exit;
    }
}

function postEvent($mysql, $json_obj, $name, $date, $time, $token) {
    // Verify CSRF token to prevent request forgery
    if(!hash_equals($_SESSION['token'], $token)){
        die("Request forgery detected"); // Stop script if tokens don't match
    }

    // Prepare SQL query to insert the new event into the 'events' table
    $stmt = $mysql->prepare("insert into events (username, event_name, event_date, event_time) values (?, ?, ?, ?)");
    if (!$stmt) {
        // If query preparation fails, display an error and stop the script
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the parameters (username, event name, date, time) and execute the query
    $stmt->bind_param('ssss', $_SESSION['username'], $name, $date, $time);
    $stmt->execute();
    $stmt->close();

    // Check if the event should be shared with another user (if 'share' parameter is set in $json_obj)
    if (isset($json_obj['share'])) {
        // Prepare SQL query to get the event ID based on the event details
        $stmt = $mysql->prepare("select id from events where username = ? and event_name = ? and event_date = ? and event_time = ?");
        if (!$stmt) {
            // If query preparation fails, display an error and stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Bind the parameters (username, event name, date, time) and execute the query to get event ID
        $stmt->bind_param('ssss', $_SESSION['username'], $name, $date, $time);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $id = (int) $row['id']; // Get the event ID
        $stmt->close();

        // Prepare SQL query to check if the user to share with exists in the 'users' table
        $stmt = $mysql->prepare("select username from users where username = ?");
        if (!$stmt) {
            // If query preparation fails, display an error and stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Bind the username to share with and execute the query
        $stmt->bind_param('s', $json_obj['share']);
        $stmt->execute();

        // If the user exists, proceed to insert the shared event
        if($stmt->fetch()) {
            $stmt->close();
            // Prepare SQL query to insert the shared event into the 'shared_events' table
            $stmt = $mysql->prepare("insert into shared_events (username, event_id) values (?, ?)");
            if (!$stmt) {
                // If query preparation fails, display an error and stop the script
                printf("Query Prep Failed: %s\n", $mysql->error);
                exit;
            }

            // Bind the shared username and event ID, then execute the query to share the event
            $stmt->bind_param('si', $json_obj['share'], $id);
            $stmt->execute();
            $stmt->close();
        } else {
            // If the user to share with does not exist, close the statement and exit
            $stmt->close();
            exit;
        }
    }

    // Respond with a success message indicating the event was posted and possibly shared
    echo json_encode(array(
        "success" => true
    ));
    exit; // End the script execution after sending the response
}

function deleteEvent($mysql, $token, $id) {
    // Check if the CSRF token matches the one in the session to prevent request forgery
    if(!hash_equals($_SESSION['token'], $token)){
        // If token mismatch, return a failure response and stop the script
        echo json_encode(array(
            "success" => false,
            "message" => "Could not delete."
        ));
        die("Request forgery detected"); // Stop execution
    }
    
    // Prepare SQL query to check the event's ownership (i.e., whether the current user owns the event)
    $stmt = $mysql->prepare("select username from events where id = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and return a failure response
        printf("Query Prep Failed: %s\n", $mysql->error);
        echo json_encode(array(
            "success" => false,
            "message" => "Could not delete."
        ));
        exit;
    }

    // Bind the event ID and execute the query
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Fetch the username of the event creator
    $resultUsername = $result->fetch_assoc();
    $stmt->close();
    
    // Check if the logged-in user is the owner of the event
    if ($_SESSION['username'] == $resultUsername['username']) {
        // If the user is the event owner, proceed to delete the event
        $stmt = $mysql->prepare("delete from events where id = ?");
        if (!$stmt) {
            // If query preparation fails, stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }
        
        // Bind the event ID and execute the delete query
        $stmt->bind_param('i', $id);
        $stmt->execute();
        $stmt->close();

        // Respond with a success message indicating the event was deleted
        echo json_encode(array(
            "success" => true
        ));
    } else {
        // If the logged-in user does not own the event, return a failure response
        echo json_encode(array(
            "success" => false,
            "message" => "Could not delete."
        ));
    }
    exit; // End the script execution after sending the response
}

function editEvent($mysql, $name, $date, $time, $token, $id) {
    // Check if the CSRF token matches the one in the session to prevent request forgery
    if(!hash_equals($_SESSION['token'], $token)) {
        die("Request forgery detected"); // Stop the script if tokens don't match
    }
    
    // Prepare SQL query to check the event's ownership (i.e., whether the current user owns the event)
    $stmt = $mysql->prepare("select username from events where id = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and return a failure response
        printf("Query Prep Failed: %s\n", $mysql->error);
        echo json_encode(array(
            "success" => false,
            "message" => "Could not update."
        ));
        exit;
    }
    
    // Bind the event ID and execute the query
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Fetch the username of the event creator
    $resultUsername = $result->fetch_assoc();
    $stmt->close();
    
    // Check if the logged-in user is the owner of the event
    if ($_SESSION['username'] == $resultUsername['username']) {
        // If the user is the event owner, proceed to update the event details
        $stmt = $mysql->prepare("update events set event_name = ?, event_date = ?, event_time = ? where id = ?");
        if (!$stmt) {
            // If query preparation fails, stop the script
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }
        
        // Bind the event details and execute the update query
        $stmt->bind_param('sssi', $name, $date, $time, $id);
        $stmt->execute();
        
        // Respond with a success message indicating the update was successful
        echo json_encode(array(
            "success" => true
        ));
        $stmt->close();
    } else {
        // If the logged-in user does not own the event, respond with a failure message
        echo json_encode(array(
            "success" => false,
            "message" => "Could not update."
        ));
    }
    exit; // End the script execution after sending the response
}

function getMonthEvents($mysql, $month, $year) {
    // Prepare SQL query to get events for a specific month and year for the logged-in user
    $stmt = $mysql->prepare("select * from events where month(event_date) = ? and year(event_date) = ? and username = ?");
    if (!$stmt) {
        // If query preparation fails, display an error and exit
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the month, year, and username parameters to the query
    $stmt->bind_param('sss', $month, $year, $_SESSION['username']);
    $stmt->execute();

    // Get the results from the query
    $result = $stmt->get_result();
    $stmt->close();

    // Fetch all results as an associative array
    $events = $result->fetch_all(MYSQLI_ASSOC);

    // Sanitize event data by applying htmlentities to each element in the array
    // This is to prevent XSS attacks and ensure safe output of user data
    $sanEvents = array_map(function($event) {
        return array_map('htmlentities', $event); // Apply htmlentities to all event fields
    }, $events);

    // Return a JSON response with the sanitized event data
    echo json_encode(array(
        "success" => true, // Indicate that the operation was successful
        "events" => $sanEvents // Include the sanitized events in the response
    ));
    exit; // End the script execution after sending the response
}
function createUser($mysql, $username, $password) {
    // Initialize variable to check if username is already in use
    $inUse = "";

    // Prepare the SQL query to check if the username already exists
    $stmt = $mysql->prepare("select username from users where username = ?");
    if (!$stmt) {
        // If the query preparation fails, display an error and exit
        printf("Query Prep Failed: %s\n", $mysql->error);
        exit;
    }

    // Bind the username parameter and execute the query
    $stmt->bind_param('s', $username);
    $stmt->execute();

    // Bind the result of the query to $inUse
    $stmt->bind_result($inUse);
    
    // Check if a result was returned, meaning the username is already taken
    if ($stmt->fetch()) {
        $stmt->close();
        // Respond with a JSON message indicating the username is taken
        echo json_encode(array(
            "success" => false,
            "message" => "Username taken"
        ));
        exit;
    } else {
        // If username is not taken, proceed to create the new user

        // Prepare the SQL query to insert the new user into the database
        $stmt = $mysql->prepare("insert into users (username, password_hash) values (?, ?)");
        if (!$stmt) {
            // If the query preparation fails, display an error and exit
            printf("Query Prep Failed: %s\n", $mysql->error);
            exit;
        }

        // Hash the password using bcrypt for secure storage
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        
        // Bind the username and hashed password to the query and execute it
        $stmt->bind_param('ss', $username, $hashedPassword);
        $stmt->execute();
        $stmt->close();

        // Call the login function to log the user in after account creation
        login($mysql, $username, $password);
        exit;
    }
}

function logout() {
    // Destroy the current session, effectively logging the user out
    session_destroy();
    
    // Return a JSON response indicating the logout was successful
    echo json_encode(array(
        "success" => true // Indicate that the logout was successful
    ));
    
    exit; // End the script execution after sending the response
}

function checkLogin() {
    // Check if the 'username' session variable is set
    if(isset($_SESSION['username'])) {
        // If session exists, return a success response with the username and token
        echo json_encode(array(
            "success" => true, // Indicate the login was successful
            "username" => htmlentities($_SESSION['username']), // Sanitize username
            "token" => htmlentities($_SESSION['token']) // Sanitize token
        ));
    } else {
        // If no session exists, return a failure response
        echo json_encode(array(
            "success" => false // Indicate login failure
        ));
    }
    exit; // End the script execution after sending the response
}
?>