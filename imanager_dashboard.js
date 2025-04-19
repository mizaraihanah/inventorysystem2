const ctx = document.getElementById('salesChart').getContext('2d');

new Chart(ctx, {
    type: 'line',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
        datasets: [{
            label: 'Monthly Sales (RM)',
            data: [5000, 7000, 6000, 9000, 15000],
            borderColor: '#0561FC',
            backgroundColor: 'rgba(5, 97, 252, 0.1)',
            tension: 0.3,
            fill: true,
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'top',
            },
        },
    }
});
