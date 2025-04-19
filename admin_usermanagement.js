document.addEventListener("DOMContentLoaded", function () {
    // Elements for Add User Modal
    const addUserBtn = document.getElementById("addUserBtn");
    const addUserModal = document.getElementById("userModal");
    const closeAddModal = document.querySelector(".close-add");
    const userForm = document.getElementById("userForm");

    // Elements for Update User Modal
    const updateUserModal = document.getElementById("updateUserModal");
    const closeUpdateModal = document.querySelector(".close-update");
    const updateUserForm = document.getElementById("updateUserForm");

    // Open Add User Modal
    addUserBtn.addEventListener("click", function () {
        addUserModal.style.display = "block";
    });

    // Close Add User Modal
    closeAddModal.addEventListener("click", function () {
        addUserModal.style.display = "none";
    });

    // Close Update User Modal
    closeUpdateModal.addEventListener("click", function () {
        updateUserModal.style.display = "none";
    });

    // Close modals when clicking outside content
    window.addEventListener("click", function (event) {
        if (event.target === addUserModal) {
            addUserModal.style.display = "none";
        } else if (event.target === updateUserModal) {
            updateUserModal.style.display = "none";
        }
    });

    // Handle Add User form submission
    userForm.addEventListener("submit", function (e) {
        e.preventDefault();

        const formData = new FormData(userForm);

        fetch("admin_adduser.php", {
            method: "POST",
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            if (data.success) {
                location.reload(); // Reload to show new user
            }
        })
        .catch(error => console.error("Error:", error));
    });

    // Handle Edit button clicks (update)
    document.querySelectorAll(".edit-btn").forEach(button => {
        button.addEventListener("click", function () {
            const userID = this.getAttribute("data-id");
            console.log("User ID for editing: " + userID);  // Log to confirm userID

            // Fetch user data when edit button is clicked
            fetch(`admin_getuser.php?userID=${userID}`)
                .then(response => response.json())
                .then(data => {
                    console.log("Fetched user data:", data);  // Log to confirm data

                    if (!data.error) {
                        // Populate the update form fields with fetched data
                        document.getElementById("updateUserID").value = data.userID;
                        document.getElementById("updateFullName").value = data.fullName;
                        document.getElementById("updateEmail").value = data.email;
                        document.getElementById("updatePhoneNumber").value = data.phoneNumber;
                        document.getElementById("updateAddress").value = data.address;
                        document.getElementById("updateRole").value = data.role;

                        // Show the modal for updating user
                        updateUserModal.style.display = "block";
                    } else {
                        alert("Failed to fetch user data: " + data.error);
                    }
                })
                .catch(error => {
                    console.error("Error fetching user data:", error);
                    alert("An error occurred while fetching user data. Please try again.");
                });
        });
    });

    // Handle Update User form submission
    updateUserForm.addEventListener("submit", function (e) {
        e.preventDefault();

        const formData = new FormData(updateUserForm);

        fetch("admin_updateuser.php", {
            method: "POST",
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);  // Show the success/error message
            if (data.success) {
                updateUserModal.style.display = "none";  // Close the modal
                location.reload(); // Reload the page to see updated user data
            }
        })
        .catch(error => console.error("Error:", error));
    });

    // Handle Delete button clicks
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function () {
            const userID = this.getAttribute("data-id");
            if (confirm("Are you sure you want to delete this user?")) {
                fetch("admin_deleteuser.php", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: `userID=${userID}`
                })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    if (data.success) {
                        location.reload();
                    }
                })
                .catch(error => console.error("Error:", error));
            }
        });
    });
});