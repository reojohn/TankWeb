
let idleTime = 0;
const idleLimit = 5; // seconds

function resetIdle() {
    idleTime = 0;
}

// Detect user activity
window.onload = resetIdle;
document.onmousemove = resetIdle;
document.onkeypress = resetIdle;
document.onclick = resetIdle;
document.onscroll = resetIdle;

// Idle checker
setInterval(function () {
    idleTime++;

    if (idleTime >= idleLimit) {
        window.location.href = "logout.php";
    }
}, 1000); // runs every 1 second


// Sidebar & Filters
const sidebar = document.getElementById('sidebar');
const auditTable = document.getElementById('audit-log-table');
const filterIP = document.getElementById('filter-ip');
const filterUser = document.getElementById('filter-user');
const filterEvent = document.getElementById('filter-event');

function toggleSidebar() {
    if (sidebar.style.left === '0px') {
        sidebar.style.left = '-250px';
    } else {
        sidebar.style.left = '0px';
    }
}

function clearFilters() {
    filterIP.value = '';
    filterUser.value = '';
    filterEvent.value = '';
    applyFilters();
}

function applyFilters() {
    const ipVal = filterIP.value.toLowerCase();
    const userVal = filterUser.value.toLowerCase();
    const eventVal = filterEvent.value.toLowerCase();

    for (const row of auditTable.tBodies[0].rows) {
        const text = row.cells[0].textContent.toLowerCase();
        let show = true;
        if (ipVal && !text.includes(ipVal)) show = false;
        if (userVal && !text.includes(userVal)) show = false;
        if (eventVal && !text.includes(eventVal)) show = false;
        row.style.display = show ? '' : 'none';
    }
}

filterIP.addEventListener('input', applyFilters);
filterUser.addEventListener('input', applyFilters);
filterEvent.addEventListener('input', applyFilters);
