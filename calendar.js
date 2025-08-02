// Check if the user is logged in when the page loads
isLoggedin();

// Global variables to store event data and current user info
let currentEvents = [];
let eventIdHolder;
let userToken;
let currentUser;
let selectedCalendar;

// Initialize current month object and display the current date
const today = new Date();
let currentMonth = new Month(today.getFullYear(), today.getMonth());
const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
$("#currentDate").text(`${months[currentMonth.month]}, ${currentMonth.year}`);

// Populate events for the current month
populateEvents(currentMonth);

// Event listener for calendar switch based on radio button
$(document).on("change", "input[name='sh']", function() {
    selectedCalendar = $("input[name='sh']:checked").val();  // Update selected calendar
    currentEvents = [];
    loadCalendar();
    populateEvents(currentMonth);  // Re-populate events based on selected calendar
});

// Previous month navigation button
$("#prev_month_btn").click(function () {
    currentMonth = currentMonth.prevMonth();  // Change to previous month
    $("#currentDate").text(`${months[currentMonth.month]}, ${currentMonth.year}`);
    populateEvents(currentMonth);  // Update events for the new month
});

// Next month navigation button
$("#next_month_btn").click(function () {
    currentMonth = currentMonth.nextMonth();  // Change to next month
    $("#currentDate").text(`${months[currentMonth.month]}, ${currentMonth.year}`);
    populateEvents(currentMonth);  // Update events for the new month
});

// Login functionality
$("#login").click(function () {
    login();
});

// User creation functionality
$("#createUser").click(function () {
    createUser();
});

// Logout functionality
$("#logout").click(function () {
    logout();
});

// Event form toggle for creating or editing events
$("#toggleEvents").click(function () {
    $("#eventForm").slideToggle();  // Toggle event form visibility
    resetEventForm();  // Reset the form fields
});

// Event creation button
$("#makeEvent").click(function () {
    let fields = ["#eventName", "#month", "#day", "#year", "#hour", "#minute", "#ampm"];
    for (field of fields) {
        if ($(field).val().trim() == "") {
            $("#invalid").text("Please fill in all fields before submitting.");
            return;  // Prevent submission if any field is empty
        }
    }
    if($("#makeEvent").text() == "Update Calendar") {
        makeEvent();  // Create new event
    } else {
        finEditEvent();  // Edit existing event
    }
});

// Calendar sharing toggle
$("#toggleShare").click(function () {
    $("#share").slideToggle();  // Toggle share calendar form visibility
});

// Share calendar submission
$("#subCalShareUser").click(function() {
    if($("#calShareUser").val().trim() == "") {
        $("#invalidShare").text("Please fill in all fields before submitting.");
        return;  // Prevent submission if share user field is empty
    }
    shareCalendar();
});

// Toggle visibility of shared calendars view
$("#toggleView").click(function () {
    $("#sharers").slideToggle();
});

// Function to share calendar with another user
function shareCalendar() {
    const sharee = $("#calShareUser").val();
    const token = $("#shareToken").val();
    const data = { 'sharee': sharee, 'token': token };
    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if(data) {
            $("#calShareUser").val("");  // Clear share user input field
            $("#share").slideToggle();  // Hide the share form
        }
    })
    .catch(err => console.error(err));  // Handle errors during the request
}

// Function to load the calendar for the current month
function loadCalendar() {
    $("#days").empty();  // Clear the existing days
    let weeks = currentMonth.getWeeks();  // Get weeks of the current month
    for (let w in weeks) {
        let days = weeks[w].getDates();  // Get the days in the week
        for (let i = 0; i < days.length; i++) {
            if (days[i].getMonth() == currentMonth.month) {
                let day = $("<div></div>").text(days[i].getDate());  // Create a day element
                if (days[i].getDate() == today.getDate() && days[i].getFullYear() == today.getFullYear() && days[i].getMonth() == today.getMonth()) {
                    day.addClass("today");  // Highlight today's date
                }
                if (currentEvents.length > 0) {
                    for (let event of currentEvents) {
                        const parts = event['event_date'].split("-");
                        const eventDate = new Date(`${parts[1]}-${parts[2]}-${parts[0]}`);
                        if (eventDate.getDate() == days[i].getDate()) {
                            const [hour, minute] = event['event_time'].split(":").map(Number);
                            const readableTime = `${hour % 12 || 12}:${minute < 10 ? "0" + minute : minute} ${hour >= 12 ? "PM" : "AM"}`;
                            let eventDiv = $("<div></div>").addClass("event");
                            eventDiv.attr('id', event['id']);
                            eventDiv.text(event['event_name'] + " " + readableTime);
                            let editButton = $("<button id='edit'></button>").addClass("edit").text("Edit");
                            let editToken = $("<input type='hidden' id='editToken' value=''>").val(userToken);
                            editButton.append(editToken);
                            let deleteButton = $("<button id='delete'></button>").addClass("delete").text("Delete");
                            let deleteToken = $("<input type='hidden' id='deleteToken' value=''>").val(userToken);
                            deleteButton.append(deleteToken);
                            deleteButton.click(function () {
                                deleteEvent(event['id']);
                                loadCalendar();  // Reload calendar after deletion
                            });
                            editButton.click(function () {
                                editEvent(event['id']);
                                loadCalendar();  // Reload calendar after edit
                            });
                            eventDiv.append(editButton);
                            eventDiv.append(deleteButton);
                            $(day).append(eventDiv);
                        }
                    }
                }
                $("#days").append(day);  // Add the day to the calendar
            } else {
                let day = $("<div></div>").text(days[i].getDate());
                day.addClass("inactive");  // Mark days outside the current month as inactive
                $("#days").append(day);
            }
        }
    }
}

// Function to populate radio buttons for shared calendars
function popRadio(sharers) {
    let radioIn = $("<input type='radio'>")
        .val(currentUser)
        .attr("id", currentUser)
        .attr("name", "sh");

    let radioLab = $("<label>")
        .attr("for", currentUser)
        .text(currentUser);

    $("#sharers").append(radioIn, radioLab, "<br>");
    for (let sharer of sharers) {
        let radioIn = $("<input type='radio'>")
            .val(sharer)
            .attr("id", sharer)
            .attr("name", "sh");

        let radioLab = $("<label>")
            .attr("for", sharer)
            .text(sharer);

        $("#sharers").append(radioIn, radioLab, "<br>");
    }
}

// Function to log the user in
function login(event) {
    const username = $("#username").val();
    const password = $("#password").val();

    const data = { 'username': username, 'password': password };

    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => data.success ? onLogin(username, data.token) : console.log(`${data.message}`))
        .catch(err => console.error(err));
}

// Function to delete an event
function deleteEvent(eventId) {
    const token = $(`#${eventId}`).children("button#delete").children("input#deleteToken").val();
    const id = eventId;
    const data = { 'token': token, 'id': id, 'delete': true };
    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => data.success && populateEvents(currentMonth))  // Re-populate events after deletion
    .catch(err => console.error(err));
}

// Function to edit an event
function editEvent(eventId) {
    let ev;
    eventIdHolder = eventId;
    for (let event of currentEvents) {
        if (event['id'] == eventId) {
            ev = event;
            break;
        }
    }
    $("#eventForm").slideToggle();
    $("#eventName").val(ev['event_name']);
    const dateParts = ev['event_date'].split("-").map(Number);
    $("#month").val(dateParts[1]);
    $("#day").val(dateParts[2]);
    $("#year").val(dateParts[0]);
    let [hour, minute] = ev['event_time'].split(":").map(Number);
    let ampm = hour >= 12 ? "PM" : "AM";
    hour = hour % 12 || 12;
    $("#hour").val(hour);
    $("#minute").val(minute);
    $("#ampm").val(ampm);
    $("#token").val($(`#${eventId}`).children("button#edit").children("input#editToken").val())
    $("#makeEvent").text("Edit Event");
}

// Finalizing event editing and submission
function finEditEvent(event) {
    $("#invalid").empty();
    const eventDay = parseInt($("#day").val(), 10);
    const eventMonth = parseInt($("#month").val(), 10) - 1;
    const eventYear = parseInt($("#year").val(), 10);
    const checkValidity = new Date(eventYear, eventMonth, 0).getDate();
    let hour = parseInt($("#hour").val(), 10);
    const minute = parseInt($("#minute").val(), 10);
    if (eventYear >= 0 && eventMonth > 0 && eventMonth <= 12 && eventDay > 0 && eventDay <= checkValidity && hour > 0 && hour <= 12 && minute >= 0 && minute < 60) {
        hour = $("#ampm").val() == "AM" ? parseInt($("#hour").val(), 10) : parseInt($("#hour").val(), 10) + 12;
        const eventName = $("#eventName").val();
        const token = $("#token").val();
        const dateTime = new Date(eventYear, eventMonth, eventDay, hour, minute);

        // Convert date to ISO string and get time string
        const date = dateTime.toISOString().split("T")[0];
        const time = dateTime.toTimeString().split(" ")[0];
        const data = { 'name': eventName, 'date': date, 'time': time, 'token': token, 'id': eventIdHolder, 'edit': true };
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    eventIdHolder = null;
                    $("#eventForm").slideToggle();
                    resetEventForm();  // Reset form after successful editing
                    populateEvents(currentMonth);  // Re-populate events for the current month
                } else {
                    $("#invalid").text("Could not edit event.");
                }
            })
            .catch(err => console.error(err));  // Handle errors
    } else {
        $("#invalid").text("Please enter valid date/time values");
    }
}

function createUser(event) {
    const username = $("#createUsername").val();
    const password = $("#createPassword").val();

    const data = { 'createUser': username, 'createPass': password };

    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => console.log(data.success ? onLogin(username, data.token) : `Account not created: ${data.message}`))
        .catch(err => console.error(err));
}

function logout(event) {
    const data = { 'logout': true };
    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => data.success ? onLogout() : console.log("Unable to logout"))
        .catch(err => console.error(err));
}

function onLogin(name, token) {
    userToken = token;
    $("#token").val(userToken);
    $("#shareToken").val(userToken);
    $("#in input").val("");
    $("#in").hide();
    currentUser = name;
    $("#currentUser").text(name);
    $("#logout").show();
    $("#eventCreator").show();
    $("#shareCal").show();
    $("#viewCal").show();
    findCalendars();
    populateEvents(currentMonth);
}

function isLoggedin() {
    const data = { 'checkLogin': true };
    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => data.success && onLogin(data.username, data.token))
        .catch(err => console.error(err));
}

function onLogout() {
    $("#shareCal").hide();
    $("#viewCal").hide();
    $("#in").show();
    $("#currentUser").empty();
    $("#logout").hide();
    $("#eventCreator").hide();
    $("#sharers").empty();
    userToken = null;
    eventIdHolder = null;
    currentEvents = [];
    loadCalendar();
}

function makeEvent(event) {
    $("#invalid").empty();
    const eventDay = parseInt($("#day").val(), 10);
    const eventMonth = parseInt($("#month").val(), 10) - 1;
    const eventYear = parseInt($("#year").val(), 10);
    const checkValidity = new Date(eventYear, eventMonth, 0).getDate();
    let hour = parseInt($("#hour").val(), 10);
    const minute = parseInt($("#minute").val(), 10);
    if (eventYear >= 0 && eventMonth > 0 && eventMonth <= 12 && eventDay > 0 && eventDay <= checkValidity && hour > 0 && hour <= 12 && minute >= 0 && minute < 60) {
        hour = $("#ampm").val() == "AM" ? parseInt($("#hour").val(), 10) : parseInt($("#hour").val(), 10) + 12;
        const eventName = $("#eventName").val();
        const token = $("#token").val();
        const dateTime = new Date(eventYear, eventMonth, eventDay, hour, minute);

        // Learned the following two lines from https://www.w3schools.com/jsref/jsref_toisostring.asp
        const date = dateTime.toISOString().split("T")[0];
        const time = dateTime.toTimeString().split(" ")[0];
        let data = { 'name': eventName, 'date': date, 'time': time, 'token': token, 'post': true };
        if($('#shareUser').val().trim() != '') {
            data.share = $("#shareUser").val();
        }
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
        .then(response => response.json())  // Get the response as JSON
        .then(data => {
            if (data.success) {
                populateEvents(currentMonth);
                $("#eventForm").slideToggle();
                resetEventForm();
            } else {
                $("#invalid").text("Could not create event.");
            }
        })
        .catch(err => console.error(err));
    } else {
        $("#invalid").text("Please enter valid date/time values");
    }
}

// Function to populate events for the specified month
function populateEvents(month) {
    // If no calendar is selected or the selected calendar is the current user
    if(selectedCalendar == null || selectedCalendar == currentUser) {
        const data = { 'month': month.month + 1, 'year': month.year };
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
            .then(response => response.json())
            .then(data => {
                // If the request is successful, update current events and check for shared events
                if (data.success) {
                    currentEvents = data.events;
                    checkShared(month);  // Check for shared events
                }
            })
            .catch(err => console.error(err));
    } else {
        // If a shared calendar is selected, get events for that calendar
        const data = { 'ymonth': month.month + 1, 'yyear': month.year,  'sharer': selectedCalendar };
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
        .then(response => response.text())
        .then(data => {
            try {
                let parsedData = JSON.parse(data);  // Parse the response data
                console.log(parsedData); // Log parsed data

                // If the request is successful, update current events and check for shared events
                if (parsedData.success) {
                    currentEvents = parsedData.events;
                    checkShared(month);  // Check for shared events
                }
            } catch (e) {
                console.error('Error parsing JSON:', data);  // Handle JSON parsing errors
            }
        })
        .catch(err => console.error(err));
    }
}

// Function to check for shared events and merge them into the current events list
function checkShared(month) {
    // If no calendar is selected or the selected calendar is the current user
    if(selectedCalendar == null || selectedCalendar == currentUser) {
        const data = { 'shareMonth': month.month + 1, 'shareYear': month.year };
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
            .then(response => response.json())
            .then(data => {
                // If the request is successful, add shared events to the current events and load the calendar
                if (data.success) {
                    currentEvents.push(...data.shared);  // Merge shared events
                    loadCalendar();  // Reload the calendar with updated events
                }
            })
            .catch(err => console.error(err));
    } else {
        // If a shared calendar is selected, get shared events for that calendar
        const data = { 'symonth': month.month + 1, 'syyear': month.year,  'sharer': selectedCalendar };
        fetch("commonFunctions.php", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: { 'content-type': 'application/json' }
        })
            .then(response => response.json())
            .then(data => {
                // If the request is successful, add shared events to the current events and load the calendar
                if (data.success) {
                    currentEvents.push(...data.shared);  // Merge shared events
                    loadCalendar();  // Reload the calendar with updated events
                }
            })
            .catch(err => console.error(err));
    }
}

// Function to reset the event form fields after an action (create or edit)
function resetEventForm() {
    let fields = ["#eventName", "#month", "#day", "#year", "#hour", "#minute", "#shareUser"];

    // Loop through all fields and clear their values
    for (field of fields) {
        $(field).val("");
    }

    $("#makeEvent").text("Update Calendar");  // Set button text to "Update Calendar"
    $("#token").val(userToken);  // Set the token field
}

// Function to find all available calendars and populate radio buttons for shared calendars
function findCalendars() {
    const data = { 'cals': true };
    fetch("commonFunctions.php", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: { 'content-type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            // If the request is successful, populate the radio buttons with available calendars
            if (data.success) {
                popRadio(data.sharers);  // Populate radio buttons with sharers
            } else {
                console.log("not found");  // If no sharers found, log message
            }
        })
        .catch(err => console.error(err));  // Handle fetch errors
}