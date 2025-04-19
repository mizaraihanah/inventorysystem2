document.addEventListener("DOMContentLoaded", function () {
    // Get the canvas element
    var ctx = document.getElementById("activityChart").getContext("2d");

    // Dummy data
    var activityData = {
        labels: ["Logins", "Profile Updates", "User Additions", "Log Deletions", "Settings Changes"],
        datasets: [{
            label: "Activity Logs",
            data: [20, 15, 10, 5, 8], // Example log counts
            backgroundColor: ["#ff6384", "#36a2eb", "#ffce56", "#4bc0c0", "#9966ff"],
            borderColor: "#ddd",
            borderWidth: 1
        }]
    };

    // Create the chart
    var activityChart = new Chart(ctx, {
        type: "bar", // Bar chart
        data: activityData,
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
});
